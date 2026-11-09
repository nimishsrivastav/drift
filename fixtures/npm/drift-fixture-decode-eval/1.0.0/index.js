// SYNTHETIC FIXTURE for drift tests. Not a real package.
'use strict';

function flatten(items) {
  return items.reduce((all, item) => all.concat(item), []);
}

module.exports = flatten;
