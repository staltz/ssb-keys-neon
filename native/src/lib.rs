// #[macro_use]
extern crate base64;
extern crate neon;
extern crate private_box;
extern crate sodiumoxide;
extern crate ssb_keyfile;
mod create;
mod generate;
mod load;
mod sig;
mod unbox;
mod utils;

use self::create::{neon_create, neon_create_sync};
use self::generate::neon_generate;
use self::load::{neon_load, neon_load_sync};
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
    cx.export_function("signObj", neon_sign_obj)?;
    cx.export_function("verifyObj", neon_verify_obj)?;
    cx.export_function("box", neon_box)?;
    cx.export_function("unbox", neon_unbox)?;
    Ok(())
});
