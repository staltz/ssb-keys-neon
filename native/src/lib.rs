// #[macro_use]
extern crate base64;
extern crate neon;
extern crate private_box;
extern crate sodiumoxide;
extern crate ssb_keyfile;
mod create;
mod generate;
mod hash;
mod load;
mod misc;
mod sig;
mod unbox;
mod utils;

use self::create::{neon_create, neon_create_sync};
use self::generate::neon_generate;
use self::hash::neon_hash;
use self::load::{neon_load, neon_load_sync};
use self::misc::neon_get_tag;
use self::sig::{neon_sign_obj, neon_verify_obj};
use self::unbox::{neon_box, neon_unbox};
use neon::prelude::*;

// FIXME: release new ssb-keyfile-rs with my PR

register_module!(mut cx, {
    private_box::init();
    cx.export_function("generate", neon_generate)?;
    cx.export_function("load", neon_load)?;
    cx.export_function("loadSync", neon_load_sync)?;
    cx.export_function("create", neon_create)?;
    cx.export_function("createSync", neon_create_sync)?;
    // cx.export_function("loadOrCreate", neon_load_or_create)?; // FIXME:
    // cx.export_function("loadOrCreateSync", neon_load_or_create_sync)?; // FIXME:
    cx.export_function("signObj", neon_sign_obj)?;
    cx.export_function("verifyObj", neon_verify_obj)?;
    cx.export_function("getTag", neon_get_tag)?; // FIXME:
    cx.export_function("hash", neon_hash)?;
    cx.export_function("box", neon_box)?;
    cx.export_function("unbox", neon_unbox)?;
    // cx.export_function("unboxKey", neon_unbox_key)?; // FIXME:
    // cx.export_function("unboxBody", neon_unbox_body)?; // FIXME:
    // cx.export_function("secretBox", neon_secret_box)?; // FIXME:
    // cx.export_function("secretUnbox", neon_secret_unbox)?; // FIXME:
    Ok(())
});
