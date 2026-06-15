// Modified slightly from
// https://github.com/andris9/rai/blob/master/lib/starttls.js
// (This code is MIT licensed.)
//
// Originally built on tls.createSecurePair(), which is deprecated and removed in
// modern Node (its SecurePair internals are gone, so pair._ssl/pair.ssl is
// undefined). Rewritten on top of tls.TLSSocket so STARTTLS works on Node 18+.

var tls = require('tls');

// From Node docs for TLS module.
var RECOMMENDED_CIPHERS = 'ECDHE-RSA-AES256-SHA:AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM';

// One secure context per tlsOptions object, shared across every upgrade on that
// server. Stable session-ticket keys let the data connection resume the TLS
// session from the control connection (RFC 5077 / TLS 1.3 PSK) — clients such
// as FileZilla require this to guard against data-connection stealing. A fresh
// context per call would rotate the ticket keys and break resumption.
var secureContextCache = new WeakMap();

function getSecureContext(options, mergedOpts) {
  var ctx = secureContextCache.get(options);
  if (!ctx) {
    ctx = tls.createSecureContext(mergedOpts);
    secureContextCache.set(options, ctx);
  }
  return ctx;
}

function starttlsServer(socket, options, callback) {
  return starttls(socket, options, callback, true);
}
function starttlsClient(socket, options, callback) {
  return starttls(socket, options, callback, false);
}

function starttls(socket, options, callback, isServer) {
  var opts = {};
  Object.keys(options).forEach(function(key) {
    opts[key] = options[key];
  });
  if (!opts.ciphers) {
    opts.ciphers = RECOMMENDED_CIPHERS;
  }

  // Stop the plaintext command parser from consuming the TLS handshake bytes;
  // TLSSocket takes over the underlying socket from here.
  socket.removeAllListeners('data');

  var secureSocket = new tls.TLSSocket(socket, {
    isServer: isServer,
    secureContext: getSecureContext(options, opts),
    requestCert: opts.requestCert || false,
    rejectUnauthorized: false,
    SNICallback: opts.SNICallback,
  });

  function onError(err) {
    secureSocket.removeListener('secure', onSecure);
    callback(err);
  }

  function onSecure() {
    secureSocket.removeListener('error', onError);

    // With no client certificate requested there is nothing to verify, so the
    // connection is authorized (matches the legacy createSecurePair behaviour
    // where verifyError() returned null on a server socket).
    if (!opts.requestCert) {
      secureSocket.authorized = true;
    }

    callback(null, secureSocket);
  }

  secureSocket.once('error', onError);
  secureSocket.on('secure', onSecure);

  return secureSocket;
}

exports.starttlsServer = starttlsServer;
exports.starttlsClient = starttlsClient;
exports.RECOMMENDED_CIPHERS = RECOMMENDED_CIPHERS;
