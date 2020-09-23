#!/usr/bin/env node

var fs = require('fs');
var pkg = require('../package.json');
pkg.name = 'ssb-keys';
var newPkgString = JSON.stringify(pkg, null, 2) + '\n';
fs.writeFileSync(__dirname + '/../package.json', newPkgString);
