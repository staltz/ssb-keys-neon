const os = require('os');
const path = require('path');
const crypto = require('crypto');
const ssbJSKeys = require('ssb-keys');
const ssbNeonKeys = require('../');

function test(ssbKeys) {
  const filename = path.join(
    os.tmpdir(),
    'ssbkeys' + Math.floor(Math.random() * 10e4),
  );
  const rainbow = 'somewhere-over-the-rainbow-way-up-high';
  const ed25519Str = 'ed25519';
  const buf = Buffer.from(rainbow);
  const hmackey = crypto.randomBytes(32);
  const ptxt = {okay: true};

  const before = Date.now();
  const alice = ssbKeys.loadOrCreateSync(filename);
  const alicePrivate = alice.private;
  const bob = ssbKeys.generate(ed25519Str);
  const bobId = bob.id;
  const bobPrivate = bob.private;
  const recps = [alice.public, bob.public];
  ssbKeys.getTag(bobId);
  ssbKeys.verifyObj(alice, ssbKeys.signObj(alicePrivate, hmackey, ptxt));
  ssbKeys.hash(rainbow);
  for (let i = 0; i < 10e3; i++) {
    ssbKeys.unbox(ssbKeys.box(ptxt, recps), bobPrivate);
    ssbKeys.secretUnbox(ssbKeys.secretBox(ptxt, buf), buf);
  }
  const after = Date.now();

  return after - before;
}

test(ssbNeonKeys); // warm up the CPU
const js1 = test(ssbJSKeys);
const ne1 = test(ssbNeonKeys);
const js2 = test(ssbJSKeys);
const ne2 = test(ssbNeonKeys);
const js3 = test(ssbJSKeys);
const ne3 = test(ssbNeonKeys);
const ssbJSDuration = Math.round((js1 + js2 + js3) / 3);
const ssbNeonDuration = Math.round((ne1 + ne2 + ne3) / 3);
const speedup = ((100 * ssbNeonDuration) / ssbJSDuration).toFixed(1);
console.log(`ssb-keys      ran in ${ssbJSDuration}ms`);
console.log(`ssb-neon-keys ran in ${ssbNeonDuration}ms (${speedup}%)`);
