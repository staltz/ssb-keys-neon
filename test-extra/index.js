var tape = require('tape');
var ssbkeys = require('../');
var fs = require('fs');
var os = require('os');
var path = require('path');

tape('create and load presigil-legacy async', function (t) {
  var keyPath = path.join(os.tmpdir(), `ssb-keys_${Date.now()}`);
  var keys = ssbkeys.generate('ed25519');
  keys.id = keys.id.substring(1);
  fs.writeFileSync(keyPath, JSON.stringify(keys));
  var k2 = ssbkeys.loadSync(keyPath);
  t.equal(k2.id, '@' + keys.id);
  t.end();
});

tape('getTag', function (t) {
  var hash = 'lFluepOmDxEUcZWlLfz0rHU61xLQYxknAEd6z4un8P8=.sha256';
  var author = '@/02iw6SFEPIHl8nMkYSwcCgRWxiG6VP547Wcp1NW8Bo=.ed25519';
  t.equal(ssbkeys.getTag(hash), 'sha256');
  t.equal(ssbkeys.getTag(author), 'ed25519');
  t.end();
});

tape('unboxKey & unboxBody', function (t) {
  var alice = ssbkeys.generate();
  var bob = ssbkeys.generate();

  var boxed = ssbkeys.box({okay: true}, [bob.public, alice.public]);
  var k = ssbkeys.unboxKey(boxed, alice.private);
  var msg = ssbkeys.unboxBody(boxed, k);
  var msg2 = ssbkeys.unbox(boxed, alice.private);
  t.deepEqual(msg, {okay: true});
  t.deepEqual(msg, msg2);
  t.end();
});

tape('loadOrCreate can load', function (t) {
  var keyPath = path.join(os.tmpdir(), `ssb-keys-1-${Date.now()}`);
  var keys = ssbkeys.generate('ed25519');
  keys.id = keys.id.substring(1);
  fs.writeFileSync(keyPath, JSON.stringify(keys));

  ssbkeys.loadOrCreate(keyPath, (err, k2) => {
    t.error(err);
    t.equal(k2.id, '@' + keys.id);
    t.end();
  });
});

tape('loadOrCreate can create', function (t) {
  var keyPath = path.join(os.tmpdir(), `ssb-keys-2-${Date.now()}`);
  t.equal(fs.existsSync(keyPath), false);

  ssbkeys.loadOrCreate(keyPath, (err, keys) => {
    t.error(err);
    t.true(keys.public.length > 20, 'keys.public is a long string');
    t.true(keys.private.length > 20, 'keys.private is a long string');
    t.true(keys.id.length > 20, 'keys.id is a long string');
    t.end();
  });
});

tape('loadOrCreateSync can load', function (t) {
  var keyPath = path.join(os.tmpdir(), `ssb-keys-3-${Date.now()}`);
  var keys = ssbkeys.generate('ed25519');
  keys.id = keys.id.substring(1);
  fs.writeFileSync(keyPath, JSON.stringify(keys));

  var k2 = ssbkeys.loadOrCreateSync(keyPath);
  t.equal(k2.id, '@' + keys.id);
  t.end();
});

tape('loadOrCreateSync can create', function (t) {
  var keyPath = path.join(os.tmpdir(), `ssb-keys-4-${Date.now()}`);
  t.equal(fs.existsSync(keyPath), false);

  var keys = ssbkeys.loadOrCreateSync(keyPath);
  t.true(keys.public.length > 20, 'keys.public is a long string');
  t.true(keys.private.length > 20, 'keys.private is a long string');
  t.true(keys.id.length > 20, 'keys.id is a long string');
  t.end();
});

tape('ssbSecretKeyToPrivateBoxSecret accepts keys object', function (t) {
  var keys = ssbkeys.generate();
  var curve = ssbkeys.ssbSecretKeyToPrivateBoxSecret(keys);
  t.true(Buffer.isBuffer(curve));
  t.equals(curve.length, 32);
  t.end();
});

tape('ssbSecretKeyToPrivateBoxSecret accepts keys.private', function (t) {
  var keys = ssbkeys.generate();
  var curve = ssbkeys.ssbSecretKeyToPrivateBoxSecret(keys.private);
  t.true(Buffer.isBuffer(curve));
  t.equals(curve.length, 32);
  t.end();
});
