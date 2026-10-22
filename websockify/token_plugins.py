import logging
import sys
import time
import re
import json
import os
import base64
from pathlib import Path
from urllib.parse import quote

try:
    import redis
except ImportError:
    redis = None

logger = logging.getLogger(__name__)

# Compact JWS algorithms accepted by JWTTokenApi. Encrypted (JWE) tokens and
# algorithms such as "none" or RSA1_5 are rejected.
ALLOWED_JWS_ALGS = frozenset({
    'RS256', 'RS384', 'RS512',
    'ES256', 'ES384', 'ES512',
    'PS256', 'PS384', 'PS512',
    'HS256', 'HS384', 'HS512',
})

TOKEN_HTTP_TIMEOUT = 5

_SOURCE_SPLIT_REGEX = re.compile(
    r'(?<=^)"([^"]+)"(?=:|$)'
    r'|(?<=:)"([^"]+)"(?=:|$)'
    r'|(?<=^)([^:]*)(?=:|$)'
    r'|(?<=:)([^:]*)(?=:|$)',
)


def parse_source_args(src):
    """It works like src.split(":") but with the ability to use a colon
    if you wrap the word in quotation marks.

    a:b:c:d -> ['a', 'b', 'c', 'd'
    a:"b:c":c -> ['a', 'b:c', 'd']
    """
    matches = _SOURCE_SPLIT_REGEX.findall(src)
    return [m[0] or m[1] or m[2] or m[3] for m in matches]


def load_maybe_file(value):
    """Return value, or the contents of a file if value is '@path'."""
    if not value or not value.startswith('@'):
        return value
    with open(os.path.expanduser(value[1:]), encoding='utf-8') as fh:
        return fh.read().rstrip('\n')


def _b64url_json(segment):
    padded = segment + '=' * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded.encode('ascii')))


class BasePlugin():
    def __init__(self, src):
        self.source = src

    def lookup(self, token):
        return None


class ReadOnlyTokenFile(BasePlugin):
    # source is a token file with lines like
    #   token: host:port
    # or a directory of such files
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._targets = None

    def _load_targets(self):
        source = Path(self.source)
        if source.is_dir():
            cfg_files = [file for file in source.iterdir() if file.is_file()]
        else:
            cfg_files = [source]

        self._targets = {}
        index = 1
        for f in cfg_files:
            with f.open() as file:
                for line in file.readlines():
                    if line and not line.startswith('#'):
                        try:
                            tok, target = re.split(r':\s', line)
                            self._targets[tok] = target.strip().rsplit(':', 1)
                        except ValueError:
                            logger.error("Syntax error in %s on line %d" % (self.source, index))
                    index += 1

    def lookup(self, token):
        if self._targets is None:
            self._load_targets()

        if token in self._targets:
            return self._targets[token]
        else:
            return None


# the above one is probably more efficient, but this one is
# more backwards compatible (although in most cases
# ReadOnlyTokenFile should suffice)
class TokenFile(ReadOnlyTokenFile):
    # source is a token file with lines like
    #   token: host:port
    # or a directory of such files
    def lookup(self, token):
        self._load_targets()

        return super().lookup(token)


class TokenFileName(BasePlugin):
    # source is a directory
    # token is filename
    # contents of file is host:port
    def __init__(self, src):
        super().__init__(src)
        if not Path(src).is_dir():
            raise Exception("TokenFileName plugin requires a directory")

    def lookup(self, token):
        token = Path(token).name
        path = Path(self.source) / token
        if path.exists():
            with path.open() as f:
                text = f.read().strip().split(':')
            return text
        else:
            return None


class BaseTokenAPI(BasePlugin):
    # source is a url with a '%s' in it where the token
    # should go

    # we import things on demand so that other plugins
    # in this file can be used w/o unnecessary dependencies

    def process_result(self, resp):
        host, port = resp.text.split(':')
        port = port.encode('ascii', 'ignore')
        return [host, port]

    def lookup(self, token):
        import requests

        url = self.source.replace('%s', quote(str(token), safe=''), 1)
        resp = requests.get(url, timeout=TOKEN_HTTP_TIMEOUT)

        if resp.ok:
            return self.process_result(resp)
        else:
            return None


class JSONTokenApi(BaseTokenAPI):
    # source is a url with a '%s' in it where the token
    # should go

    def process_result(self, resp):
        resp_json = resp.json()
        return (resp_json['host'], resp_json['port'])


class JWTTokenApi(BasePlugin):
    """Resolve a compact JWS token to a host/port pair.

    Encrypted JWE tokens are rejected. The same key is used only to verify
    signatures (JWS), never to decrypt. Allowed algorithms are listed in
    ALLOWED_JWS_ALGS.
    """

    def lookup(self, token):
        try:
            from jwcrypto import jwt, jwk

            key = jwk.JWK()

            try:
                with open(self.source, 'rb') as key_file:
                    key_data = key_file.read()
            except Exception as e:
                logger.error("Error loading key file: %s" % str(e))
                return None

            try:
                key.import_from_pem(key_data)
            except Exception:
                try:
                    key.import_key(k=key_data.decode('utf-8'), kty='oct')
                except Exception:
                    logger.error('Failed to correctly parse key data!')
                    return None

            try:
                key['use'] = 'sig'
            except Exception:
                pass

            try:
                parts = str(token).split('.')
                if len(parts) != 3:
                    logger.error("Rejected JWT: expected compact JWS with 3 segments")
                    return None

                parsed_header = _b64url_json(parts[0])
                if 'enc' in parsed_header:
                    logger.error("Rejected JWT: encrypted (JWE) tokens are not accepted")
                    return None

                alg = parsed_header.get('alg')
                if alg not in ALLOWED_JWS_ALGS:
                    logger.error("Rejected JWT: algorithm not allowed")
                    return None

                token = jwt.JWT(key=key, jwt=token, algs=list(ALLOWED_JWS_ALGS))
                parsed = json.loads(token.claims)

                if 'nbf' in parsed:
                    if time.time() < parsed['nbf']:
                        logger.warning('Token can not be used yet!')
                        return None

                if 'exp' in parsed:
                    if time.time() > parsed['exp']:
                        logger.warning('Token has expired!')
                        return None

                return (parsed['host'], parsed['port'])
            except Exception as e:
                logger.error("Failed to parse token: %s" % str(e))
                return None
        except ImportError:
            logger.error("package jwcrypto not found, are you sure you've installed it correctly?")
            return None


class TokenRedis(BasePlugin):
    """Token plugin based on the Redis in-memory data store.

    The token source is in the format:

        host[:port[:db[:password[:namespace[:ssl]]]]]

    where port, db, password, namespace and ssl are optional. If port or db are left empty
    they will take its default value, ie. 6379 and 0 respectively.

    If your redis server is using the default port (6379) then you can use:

        my-redis-host

    In case you need to authenticate with the redis server and you are using
    the default database and port you can use:

        my-redis-host:::verysecretpass

    Prefix the password with '@' to read it from a file instead of the command
    line:

        my-redis-host:::@/run/secrets/redis-password

    You can also specify a namespace. In this case, the tokens
    will be stored in the format '{namespace}:{token}'

        my-redis-host::::my-app-namespace

    Or if your namespace is nested, you can wrap it in quotes:

        my-redis-host::::"first-ns:second-ns"

    Enable TLS to Redis with a sixth field (1/true/ssl/yes):

        my-redis-host:6380:0:@/run/secrets/redis-password::ssl

    In the more general case you will use:

        my-redis-host:6380:1:verysecretpass:my-app-namespace

    The TokenRedis plugin expects the format of the target in one of these two
    formats:

    - JSON

        {"host": "target-host:target-port"}

    - Plain text

        target-host:target-port

    Prepare data with:

        redis-cli set my-token '{"host": "127.0.0.1:5000"}'

    Verify with:

        redis-cli --raw get my-token

    Spawn a test "server" using netcat

        nc -l 5000 -v

    Note: This Token Plugin depends on the 'redis' module, so you have
    to install it before using this plugin:

          pip install redis
    """
    def __init__(self, src):
        if redis is None:
            logger.error("Unable to load redis module")
            sys.exit()
        # Default values
        self._port = 6379
        self._db = 0
        self._password = None
        self._namespace = ""
        self._ssl = False
        try:
            fields = parse_source_args(src)
            if len(fields) == 1:
                self._server = fields[0]
            elif len(fields) == 2:
                self._server, self._port = fields
                if not self._port:
                    self._port = 6379
            elif len(fields) == 3:
                self._server, self._port, self._db = fields
                if not self._port:
                    self._port = 6379
                if not self._db:
                    self._db = 0
            elif len(fields) == 4:
                self._server, self._port, self._db, self._password = fields
                if not self._port:
                    self._port = 6379
                if not self._db:
                    self._db = 0
                if not self._password:
                    self._password = None
            elif len(fields) == 5:
                self._server, self._port, self._db, self._password, self._namespace = fields
                if not self._port:
                    self._port = 6379
                if not self._db:
                    self._db = 0
                if not self._password:
                    self._password = None
                if not self._namespace:
                    self._namespace = ""
            elif len(fields) == 6:
                self._server, self._port, self._db, self._password, self._namespace, ssl_flag = fields
                if not self._port:
                    self._port = 6379
                if not self._db:
                    self._db = 0
                if not self._password:
                    self._password = None
                if not self._namespace:
                    self._namespace = ""
                self._ssl = ssl_flag.lower() in ('1', 'true', 'ssl', 'yes')
            else:
                raise ValueError
            self._port = int(self._port)
            self._db = int(self._db)
            self._password = load_maybe_file(self._password)
            if self._namespace:
                self._namespace += ":"

            logger.info("TokenRedis backend initialized (%s:%s)" %
                        (self._server, self._port))
        except ValueError:
            logger.error("The provided --token-source='%s' is not in the "
                         "expected format <host>[:<port>[:<db>[:<password>[:<namespace>[:<ssl>]]]]]" %
                         src)
            sys.exit()

    def lookup(self, token):
        if redis is None:
            logger.error("package redis not found, are you sure you've installed them correctly?")
            sys.exit()

        logger.info("resolving token")
        client = redis.Redis(host=self._server, port=self._port,
                             db=self._db, password=self._password,
                             ssl=self._ssl)
        stuff = client.get(self._namespace + token)
        if stuff is None:
            return None
        else:
            responseStr = stuff.decode("utf-8").strip()
            logger.debug("response from redis : %s" % responseStr)
            if responseStr.startswith("{"):
                try:
                    combo = json.loads(responseStr)
                    host, port = combo["host"].split(":")
                except ValueError:
                    logger.error("Unable to decode JSON token: %s" %
                                 responseStr)
                    return None
                except KeyError:
                    logger.error("Unable to find 'host' key in JSON token: %s" %
                                 responseStr)
                    return None
            elif re.match(r'\S+:\S+', responseStr):
                host, port = responseStr.split(":")
            else:
                logger.error("Unable to parse token: %s" % responseStr)
                return None
            logger.debug("host: %s, port: %s" % (host, port))
            return [host, port]


class UnixDomainSocketDirectory(BasePlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._dir_path = Path(self.source).absolute()

    def lookup(self, token: str):
        try:
            import stat

            dir_path = self._dir_path.resolve()
            if not dir_path.is_dir():
                return None

            # Token must be a single path segment (no traversal).
            if Path(token).name != token or token in ('.', '..', ''):
                return None

            uds_path = (dir_path / token).resolve()
            try:
                uds_path.relative_to(dir_path)
            except ValueError:
                return None

            if not uds_path.exists():
                return None

            if not stat.S_ISSOCK(uds_path.stat().st_mode):
                return None

            return ['unix_socket', uds_path]
        except Exception as e:
            logger.error("Error finding unix domain socket: %s" % str(e))
            return None
