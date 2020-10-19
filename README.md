# ssb-keys-neon

> A drop-in replacement of `ssb-keys`, implemented in Rust and delivered as a native module in Node.js

```
npm install ssb-keys-neon
```

## Motivation

It would make a lot of sense for SSB to be implemented in Rust, a language for safety and performance. [Sunrise Choir](https://github.com/sunrise-choir/) has written a lot of SSB modules in Rust, but these are not yet running in production, simply because it requires a lot of work to migrate from Node.js (and/or Electron) to Rust.

[Neon](https://neon-bindings.com) allows you to create native modules for Node.js written in Rust. This is great, because it allows us to use Sunrise Choir's modules directly inside Node.js!

ssb-keys-neon does exactly that, it runs [ssb-crypto](https://github.com/sunrise-choir/ssb-crypto), [ssb-keyfile](https://github.com/sunrise-choir/ssb-keyfile), [ssb-multiformats](https://github.com/sunrise-choir/ssb-multiformats) (Rust crates) under the hood, but provides an API that **perfectly mirrors** that of `ssb-keys`. There is no code you need to migrate, just replace `ssb-keys` with `ssb-keys-neon` and it's done.

We even run the same test suite for `ssb-keys` on `ssb-keys-neon`.

## Usage

There are two ways you can use this npm package.

### Option 1: (easiest) automatically replace

In your **package.json**, assuming you already have `ssb-keys`, you can replace its *implementation* by pointing to the GitHub repo for `ssb-keys-neon`:

```diff
   // ...
   "dependencies": {
     "ssb-ebt": "^5.6.7",
     "ssb-friends": "^4.1.4",
     "ssb-invite": "^2.1.3",
-    "ssb-keys": "7.2.0",
+    "ssb-keys": "staltz/ssb-keys-neon#replace-7.2.0",
     "ssb-lan": "^0.2.0",
     "ssb-logging": "^1.0.0",
     "ssb-markdown": "^6.0.4",
   }
   // ...
```

This is the easiest method because you only need to change `package.json`, your code can still `require('ssb-keys')` and under the hood it will load `ssb-keys-neon`.

Note that you **cannot specify version ranges**. If you previously had `"ssb-keys": "7.x.x"`, you will have to specify an exact version when you write `"staltz/ssb-keys-neon#replace-7.2.0"`, you cannot write `"staltz/ssb-keys-neon#replace-7.x.x"`.

### Option 2: manually replace

This method gives you more control over the usage of `ssb-keys-neon`, as well as allows you to specify version ranges. Just *remove ssb-keys* from your package.json, and *add ssb-keys-neon*:

```diff
   // ...
   "dependencies": {
     "ssb-ebt": "^5.6.7",
     "ssb-friends": "^4.1.4",
     "ssb-invite": "^2.1.3",
-    "ssb-keys": "8.0.0",
+    "ssb-keys-neon": ">=8.0.0-1",
     "ssb-lan": "^0.2.0",
     "ssb-logging": "^1.0.0",
     "ssb-markdown": "^6.0.4",
   }
   // ...
```

**Then**, you also have to replace usages of ssb-keys manually in JavaScript source files:

```diff
-var ssbKeys = require('ssb-keys')
+var ssbKeys = require('ssb-keys-neon')

 // ...
```

## Versioning and support

`ssb-keys-neon@X.Y.Z-num` is compatible with `ssb-keys@X.Y.Z`. Versions older than 8.0.0 still use the old name `ssb-neon-keys` so be sure to type it correctly.

Versions of ssb-keys that are mirrored by ssb-keys-neon currently include (and which platforms are guaranteed to be supported):

<details>
<summary>8.0.0 (click here to see which platforms are supported)</summary>

As of `ssb-keys-neon@8.0.0-5`

- macOS (darwin-x64)
  - Node 10.x
  - Node 12.x
  - Node 14.x
  - Electron 7.x
  - Electron 8.x
  - Electron 9.x
  - Electron 10.x
- Linux (linux-x64)
  - Node 10.x
  - Node 12.x
  - Node 14.x
  - Electron 7.x
  - Electron 8.x
  - Electron 9.x
  - Electron 10.x
- Windows (win32-x64)
  - Node 10.x
  - Node 12.x
  - Node 14.x
  - Electron 7.x
  - Electron 8.x
  - Electron 9.x
  - Electron 10.x

</details>

<details>
<summary>7.2.2 (click here to see which platforms are supported)</summary>

**As of `ssb-neon-keys@7.2.2-2`**

- macOS (darwin-x64)
  - Node 10.x
  - Node 12.x
  - Node 14.x
  - Electron 7.x
  - Electron 8.x
  - Electron 9.x
  - Electron 10.x
- Linux (linux-x64)
  - Node 10.x
  - Node 12.x
  - Node 14.x
  - Electron 7.x
  - Electron 8.x
  - Electron 9.x
  - Electron 10.x
- Windows (win32-x64)
  - Node 10.x
  - Node 12.x
  - Node 14.x
  - Electron 7.x
  - Electron 8.x
  - Electron 9.x
  - Electron 10.x

</details>

<details>
<summary>7.2.1 (click here to see which platforms are supported)</summary>

**As of `ssb-neon-keys@7.2.1-3`**

- macOS (darwin-x64)
  - Node 10.x
  - Node 12.x
  - Node 14.x
  - Electron 7.x
  - Electron 8.x
  - Electron 9.x
  - Electron 10.x
- Linux (linux-x64)
  - Node 10.x
  - Node 12.x
  - Node 14.x
  - Electron 7.x
  - Electron 8.x
  - Electron 9.x
  - Electron 10.x
- Windows (win32-x64)
  - Node 10.x
  - Node 12.x
  - Node 14.x
  - Electron 7.x
  - Electron 8.x
  - Electron 9.x
  - Electron 10.x

</details>

<details>
<summary>7.2.0 (click here to see which platforms are supported)</summary>

**As of `ssb-neon-keys@7.2.0-18`**

- macOS (darwin-x64)
  - Node 10.x
  - Node 12.x
  - Node 14.x
  - Electron 7.x
  - Electron 8.x
  - Electron 9.x
  - Electron 10.x
- Linux (linux-x64)
  - Node 10.x
  - Node 12.x
  - Node 14.x
  - Electron 7.x
  - Electron 8.x
  - Electron 9.x
  - Electron 10.x
- Windows (win32-x64)
  - Node 10.x
  - Node 12.x
  - Node 14.x
  - Electron 7.x
  - Electron 8.x
  - Electron 9.x
  - Electron 10.x

</details>

## License

AGPL-3.0
