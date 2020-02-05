// #[macro_use]
extern crate base64;
extern crate neon;
extern crate sodiumoxide;
extern crate ssb_keyfile;
mod create;
mod generate;
mod load;
mod utils;

use self::create::{neon_create, neon_create_sync};
use self::generate::neon_generate;
use self::load::{neon_load, neon_load_sync};
use neon::prelude::*;

// pub fn keypair_from_seed(seed: &Seed) -> (PublicKey, SecretKey) {

register_module!(mut cx, {
    cx.export_function("generate", neon_generate)?;
    cx.export_function("load", neon_load)?;
    cx.export_function("loadSync", neon_load_sync)?;
    cx.export_function("create", neon_create)?;
    cx.export_function("createSync", neon_create_sync)?;
    Ok(())
});
