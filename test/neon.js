var tape = require('tape');
var ssbkeys = require('../');

tape('getTag', function (t) {
  var hash = 'lFluepOmDxEUcZWlLfz0rHU61xLQYxknAEd6z4un8P8=.sha256';
  var author = '@/02iw6SFEPIHl8nMkYSwcCgRWxiG6VP547Wcp1NW8Bo=.ed25519';
  t.equal(ssbkeys.getTag(hash), 'sha256');
  t.equal(ssbkeys.getTag(author), 'ed25519');
  t.end();
});
