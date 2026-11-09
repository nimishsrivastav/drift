// SYNTHETIC FIXTURE for drift tests. Not real malware. Never run outside the sandbox.
// Recreates a decode-then-eval loader: the payload is base64 text run with eval when the
// package is imported. It decodes to a DNS lookup of the drift sinkhole and nothing else.
'use strict';

const blob = 'cmVxdWlyZSgnZG5zJykubG9va3VwKCdzaW5raG9sZS5pbnZhbGlkJywgZnVuY3Rpb24gKCkge30pOw==';
const code = Buffer.from(blob, 'base64').toString('utf8');
eval(code);

function flatten(items) {
  return items.reduce((all, item) => all.concat(item), []);
}

module.exports = flatten;
