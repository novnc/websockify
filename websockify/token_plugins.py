import logging
import os
import sys
import time
import re
import json

logger = logging.getLogger(__name__)


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
        if os.path.isdir(self.source):
            cfg_files = [os.path.join(self.source, f) for
                         f in os.listdir(self.source)]
        else:
            cfg_files = [self.source]

        self._targets = {}
        index = 1
        for f in cfg_files:
            for line in [l.strip() for l in open(f).readlines()]:
                if line and not line.startswith('#'):
                    try:
                        tok, target = re.split(':\s', line)
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


class BaseTokenAPI(BasePlugin):
    # source is a url with a '%s' in it where the token
    # should go

    # we import things on demand so that other plugins
    # in this file can be used w/o unnecessary dependencies

    def process_result(self, resp):
        host, port = resp.text.split(':')
        port = port.encode('ascii','ignore')
        return [ host, port ]

    def lookup(self, token):
        import requests

        resp = requests.get(self.source % token)

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
    # source is a JWT-token, with hostname and port included
    # Both JWS as JWE tokens are accepted. With regards to JWE tokens, the key is re-used for both validation and decryption.

    def lookup(self, token):
        try:
            from jwcrypto import jwt, jwk
            import json

            key = jwk.JWK()

            try:
                with open(self.source, 'rb') as key_file:
                    key_data = key_file.read()
            except Exception as e:
                logger.error("Error loading key file: %s" % str(e))
                return None

            try:
                key.import_from_pem(key_data)
            except:
                try:
                    key.import_key(k=key_data.decode('utf-8'),kty='oct')
                except:
                    logger.error('Failed to correctly parse key data!')
                    return None

            try:
                token = jwt.JWT(key=key, jwt=token)
                parsed_header = json.loads(token.header)

                if 'enc' in parsed_header:
                    # Token is encrypted, so we need to decrypt by passing the claims to a new instance
                    token = jwt.JWT(key=key, jwt=token.claims)

                parsed = json.loads(token.claims)

                if 'nbf' in parsed:
                    # Not Before is present, so we need to check it
                    if time.time() < parsed['nbf']:
                        logger.warning('Token can not be used yet!')
                        return None

                if 'exp' in parsed:
                    # Expiration time is present, so we need to check it
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

        host[:port[:db[:password]]]

    where port and password are optional.

    If your redis server is using the default port (6379) then you can use:

        my-redis-host

    In case you need to authenticate with the redis server you will have to
    specify also the port and db:

        my-redis-host:6379:0:verysecretpass

    The TokenRedis plugin expects the format of the data in a form of json.

    Prepare data with:
        redis-cli set hello '{"host":"127.0.0.1:5000"}'

    Verify with:
        redis-cli --raw get hello

    Spawn a test "server" using netcat
        nc -l 5000 -v

    Note: you have to install also the 'redis' module
          pip install redis
    """
    def __init__(self, src):
        try:
            import redis
        except ImportError:
            logger.error("Unable to load redis module")
            sys.exit()
        # Default values
        self._port = 6379
        self._db = 0
        self._password = None
        try:
            fields = src.split(":")
            if len(fields) == 1:
                self._server = fields[0]
            elif len(fields) == 2:
                self._server, self._port = fields
            elif len(fields) == 3:
                self._server, self._port, self._db = fields
            elif len(fields) == 4:
                self._server, self._port, self._db, self._password = fields
            else:
                raise ValueError
            self._port = int(self._port)
            self._db = int(self._db)
            logger.info("TokenRedis backend initilized (%s:%s)" %
                  (self._server, self._port))
        except ValueError:
            logger.error("The provided --token-source='%s' is not in the "
                         "expected format <host>[:<port>[:<db>[:<password>]]]" %
                         src)
            sys.exit()

    def lookup(self, token):
        try:
            import redis
        except ImportError:
            logger.error("package redis not found, are you sure you've installed them correctly?")
            sys.exit()

        logger.info("resolving token '%s'" % token)
        client = redis.Redis(host=self._server, port=self._port,
                             db=self._db, password=self._password)
        stuff = client.get(token)
        if stuff is None:
            return None
        else:
            responseStr = stuff.decode("utf-8")
            logger.debug("response from redis : %s" % responseStr)
            combo = json.loads(responseStr)
            (host, port) = combo["host"].split(':')
            logger.debug("host: %s, port: %s" % (host,port))
            return [host, port]


class UnixDomainSocketDirectory(BasePlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._dir_path = os.path.abspath(self.source)

    def lookup(self, token):
        try:
            import stat

            if not os.path.isdir(self._dir_path):
                return None

            uds_path = os.path.abspath(os.path.join(self._dir_path, token))
            if not uds_path.startswith(self._dir_path):
                return None

            if not os.path.exists(uds_path):
                return None

            if not stat.S_ISSOCK(os.stat(uds_path).st_mode):
                return None

            return [ 'unix_socket', uds_path ]
        except Exception as e:
                logger.error("Error finding unix domain socket: %s" % str(e))
                return None
