/*
 * An auth plugin must be a function which returns a function conforming to the
 * requirements of the `verifyClients` option on ws.WebSocket.Server.
 *
 * See: https://github.com/websockets/ws/blob/master/doc/ws.md
 *
 * If websockify is provided with an --auth-source argument, this will be
 * passed to the auth plugin as its first argument.
 *
 */

const querystring = require('querystring');
const fs = require('fs');

function urlTokenMatch(url, token, verbose=false) {
    /**
     * Parse the url path, extract the `token` querystring value, and check if
     * it matches the token argument. If verbose is set to true, log messages
     * are enabled.
     *
     * Args:
     *      url (string): the path section of the URL
     *      token (string): the token which the token provided in the URL should
     *          match
     *      verbose (boolean): If True, extra console.log messages will be output
     */
    let splitUrl = url.split("?")
    if (splitUrl.length !== 2) {
        if (verbose) {
            console.log("Permission denied. No token provided.");
        }
        return false;
    }
    let qs = splitUrl[1];
    let qs_parsed = querystring.parse(qs);
    let success = (qs_parsed.token === token);
    if (verbose) {
        if (!success) {
            console.log("Permission denied for token: " + qs_parsed.token);
        } else {
            console.log("Permission granted for token: " + qs_parsed.token);
        }
    }
    return success;
}

exports.tokenAuth = function tokenAuth(source) {
    /**
     * Authorisation plugin which validates the token query parameter against
     * a token provided as the argument to the `--auth-source` command line
     * argument.
     */
    return {
        authenticate(info) {
            const token = source;
            return urlTokenMatch(info.req.url, token, true);
        }
    }
}

exports.TokenAuthClass = class TokenAuthClass {
    /**
     * Class-based equivalent of tokenAuth
     */

    constructor(source) {
        this.source = source;
    }

    authenticate(info) {
        const token = this.source;
        console.log(token)
        return urlTokenMatch(info.req.url, token, true);
    }

}

exports.tokenAuthEnv = function tokenAuthEnv(source) {
    /**
     * Authorisation plugin which validates the token query parameter against
     * a token which is the value of an environment variable. The name of this
     * environment variable is specified as the argument to the command line
     * argument `--auth-source`
     */
    return function(info) {
        let token = process.env[source];
        return urlTokenMatch(info.req.url, token, true);
    }
}

exports.tokenAuthFile = function tokenEnvFile(source) {
    /**
     * Authorisation plugin which validates the token query parameter against a
     * token which is contained in a text file, the path to which is specified
     * as the value of the `--auth-source` command line argument
     */
    return function(info, cb) {
        fs.readFile(source, 'utf8', function(err, data) {
            if (err) {
                console.log(err);
                cb(false);
            } else {
                let token = data.trim();
                let success = urlTokenMatch(info.req.url, token, true);
                cb(success);
            }
        });
    }
}