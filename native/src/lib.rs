// #[macro_use]
extern crate base64;
extern crate neon;
extern crate private_box;
extern crate sodiumoxide;
extern crate ssb_crypto;
extern crate ssb_keyfile;
mod generate;
mod hash;
mod load_create;
mod misc;
mod secret;
mod sig;
mod unbox;
mod utils;

use self::generate::neon_generate;
use self::hash::neon_hash;
use self::load_create::{
    neon_create, neon_create_sync, neon_load, neon_load_or_create, neon_load_or_create_sync,
    neon_load_sync,
};
use self::misc::neon_get_tag;
use self::secret::{neon_secret_box, neon_secret_unbox};
use self::sig::{neon_sign_obj, neon_verify_obj};
use self::unbox::{neon_box, neon_unbox, neon_unbox_body, neon_unbox_key};
use neon::prelude::*;

// FIXME: release new ssb-keyfile-rs with my PR

register_module!(mut cx, {
    private_box::init();
    cx.export_function("generate", neon_generate)?;
    cx.export_function("load", neon_load)?;
    cx.export_function("loadSync", neon_load_sync)?;
    cx.export_function("create", neon_create)?;
    cx.export_function("createSync", neon_create_sync)?;
    cx.export_function("loadOrCreate", neon_load_or_create)?;
    cx.export_function("loadOrCreateSync", neon_load_or_create_sync)?;
    cx.export_function("signObj", neon_sign_obj)?;
    cx.export_function("verifyObj", neon_verify_obj)?;
    cx.export_function("getTag", neon_get_tag)?;
    cx.export_function("hash", neon_hash)?;
    cx.export_function("box", neon_box)?;
    cx.export_function("unbox", neon_unbox)?;
    cx.export_function("unboxKey", neon_unbox_key)?;
    cx.export_function("unboxBody", neon_unbox_body)?;
    cx.export_function("secretBox", neon_secret_box)?;
    cx.export_function("secretUnbox", neon_secret_unbox)?;
    Ok(())
});
