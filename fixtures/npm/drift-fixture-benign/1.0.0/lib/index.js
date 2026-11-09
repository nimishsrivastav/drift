// SYNTHETIC FIXTURE for drift tests. Not a real package.
'use strict';

const https = require('https');

// Fetches a status line, only when called. The host is the drift sinkhole.
function status(callback) {
  https.get({ host: 'sinkhole.invalid', path: '/status' }, (res) => callback(null, res.statusCode)).on('error', callback);
}

function label(name, value) {
  return name + ': ' + value;
}

module.exports = { status, label };
