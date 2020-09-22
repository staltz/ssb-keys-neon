#!/usr/bin/env node

var fs = require('fs');
var os = require('os');
var path = require('path');
var mkdirp = require('mkdirp');
var nodeAbi = require('node-abi');

var vars = (process.config && process.config.variables) || {};
var abi = process.versions.modules;
var runtime = isElectron() ? 'electron' : 'node';
var arch = os.arch();
var platform = os.platform();
var libc = process.env.LIBC || (isAlpine(platform) ? 'musl' : 'glibc');
var armv =
  process.env.ARM_VERSION || (arch === 'arm64' ? '8' : vars.arm_version) || '';
var uv = (process.versions.uv || '').split('.')[0];

var orig = path.join('.', 'native', 'index.node');
if (!fs.existsSync(orig)) {
  throw new Error(
    'there is no ./native/index.node built by Neon to mark as prebuild',
  );
}
var dirname = path.join('.', 'prebuilds', platform + '-' + arch);
mkdirp.sync(dirname);
var dest = path.join(dirname, getFilename());
fs.copyFile(orig, dest, (err) => {
  if (err) throw err;
});

function isElectron() {
  if (process.versions && process.versions.electron) return true;
  if (process.env.ELECTRON_RUN_AS_NODE) return true;
  if (process.env.npm_config_runtime === 'electron') return true;
  return (
    typeof window !== 'undefined' &&
    window.process &&
    window.process.type === 'renderer'
  );
}

function isAlpine(platform) {
  return platform === 'linux' && fs.existsSync('/etc/alpine-release');
}

function getFilename() {
  var target = isElectron()
    ? process.env.npm_config_target
    : process.versions.node;
  var tags = [];
  tags.push(runtime);
  tags.push('abi' + nodeAbi.getAbi(target, runtime));
  // if (uv) tags.push('uv' + uv); // FIXME: support?
  if (armv) tags.push('armv' + abi);
  // if (libc) tags.push(libc); // FIXME: support?
  return tags.join('.') + '.node';
}
