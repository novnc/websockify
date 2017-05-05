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

exports.tokenAuth = function tokenAuth(source) {
    return function(info) {
        console.log(info.req.url);
        let splitUrl = info.req.url.split("?")
        if (splitUrl.length !== 2) {
            return false;
        }
        let qs = splitUrl[1];
        let qs_parsed = querystring.parse(qs)
        console.log(qs_parsed)
        return (qs_parsed.token === source);
    }
}

