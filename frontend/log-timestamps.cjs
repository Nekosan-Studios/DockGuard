// Prepend ISO-8601 timestamps to console output.
// Loaded via: node --require ./log-timestamps.cjs build/index.js
'use strict';

const orig = {
  log: console.log,
  warn: console.warn,
  error: console.error,
};

for (const method of ['log', 'warn', 'error']) {
  console[method] = (...args) => {
    orig[method](new Date().toISOString(), ...args);
  };
}
