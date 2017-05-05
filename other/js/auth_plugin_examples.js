/*
 * An auth plugin must be a function which returns a function conforing to the
 * requirements of the `verifyClients` option on ws.WebSocket.Server.
 *
 * See: https://github.com/websockets/ws/blob/master/doc/ws.md
 *
 * If websockify is provided with an --auth-source argument, this will be
 * passed to the auth plugin as its first argument.
 *
 */

const querystring = require('querystring');
fs = require('fs');

function urlTokenMatch(url, token, verbose=false) {
    let splitUrl = url.split("?")
    if (splitUrl.length !== 2) {
        return ["", false];
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
    return function(info) {
        let token = source;
        return urlTokenMatch(info.req.url, token, true);
    }
}

exports.tokenAuthEnv = function tokenAuthEnv(source) {
    return function(info) {
        let token = process.env[source];
        return urlTokenMatch(info.req.url, token, true);
    }
}

exports.tokenAuthFile = function tokenEnvFile(source) {
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