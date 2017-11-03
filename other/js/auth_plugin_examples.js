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

const fs = require('fs');

class BaseAuth {

    constructor(source) {
        this.source = source;
    }

    authenticate(info) {
        return false;
    }

}

/**
 * Authorisation plugin which validates origin of the request against a single
 * permitted origin
 */
exports.AuthByOrigin = class AuthByOrigin extends BaseAuth {

    authenticate(info) {
        const expected = this.source;
        const actual = info.origin;
        const allow = expected === actual;
        if (!allow) {
            console.log("Denied access from origin: " + actual)
        }
        return allow;
    }

}

/**
 * Function-based version of AuthByOrigin
 */
exports.AuthByOriginFunctional = function(source) {
    return {
        authenticate(info) {
            const expected = source;
            const actual = info.origin;
            const success = expected === actual;
            if (!success) {
                console.log("Denied access from origin: " + actual)
            }
            return success;
        }
    };
}

/**
 * Authorisation plugin which validates the origin of the request against
 * an origin contained in a text file, the path to which is specified
 * as the value of the `--auth-source` command line argument
 */
exports.AuthByOriginFile = class AuthByOriginFile extends BaseAuth {


    authenticate(info, cb) {
        fs.readFile(this.source, 'utf8', function(err, data) {
            if (err) {
                console.log(err);
                cb(false);
            } else {
                const expected = data.trim();
                const actual = info.origin;
                const success = expected === actual;
                if (!success) {
                    console.log("Denied access from origin: " + actual);
                }
                cb(success);
            }
        })
    }

}
