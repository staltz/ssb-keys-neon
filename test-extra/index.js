let tape = require('tape');
let ssbKeys = require('../');
let path = require('path');
let os = require('os');
let fs = require('fs');

// This file was used when ssb-keys was lacking tests for some public APIs.
// Nowadays we update ssb-keys tests to cover everything.
// You can still use this file to add ad-hoc tests if you need

const keyPath = path.join(os.tmpdir(), `ssb-keys-${Date.now()}`);

tape("don't create dir for fully-specified path", function (t) {
  t.false(fs.existsSync(keyPath));
  ssbKeys.loadOrCreate(keyPath, (err, keys) => {
    t.error(err);
    t.true(fs.lstatSync(keyPath).isFile());

    ssbKeys.loadOrCreate(keyPath, (err, keys) => {
      t.error(err);
      t.equal(keys.public.length, 52);
      fs.unlinkSync(keyPath);
      t.end();
    });
  });
});
