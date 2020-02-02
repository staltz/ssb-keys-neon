// #[macro_use]
extern crate base64;
extern crate neon;
extern crate sodiumoxide;
// extern crate ssb_crypto; // TODO do we need this?
extern crate ssb_keyfile;

use neon::prelude::*;
use sodiumoxide::crypto::sign::ed25519;
use sodiumoxide::crypto::sign::ed25519::{PublicKey, SecretKey};
use sodiumoxide::crypto::sign::Seed;
use ssb_keyfile::Error as SSBError;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::io::{Error, ErrorKind};
use std::path::Path;

// pub fn keypair_from_seed(seed: &Seed) -> (PublicKey, SecretKey) {

// TODO this should probably be public in ssb-keyfile
fn encode_key(bytes: &[u8]) -> String {
    let mut out = base64::encode_config(bytes, base64::STANDARD);
    out.push_str(".ed25519");
    out
}

fn make_keys_obj<'a, 'b, 'c>(
    cx: &mut ComputeContext<'b, 'c>,
    pk: &'a PublicKey,
    sk: &'a SecretKey,
) -> JsResult<'b, JsObject> {
    let keys_obj = JsObject::new(cx);
    let curve_val = cx.string("ed25519");
    let id_val = cx.string({
        let mut p = encode_key(&pk.0);
        p.insert(0, '@');
        p
    });
    let private_val = cx.string(encode_key(&sk.0));
    let public_val = cx.string(encode_key(&pk.0));
    keys_obj.set(cx, "curve", curve_val)?;
    keys_obj.set(cx, "id", id_val)?;
    keys_obj.set(cx, "private", private_val)?;
    keys_obj.set(cx, "public", public_val)?;
    Ok(keys_obj)
}

fn generate(mut cx: FunctionContext) -> JsResult<JsObject> {
    // First argument: curve (default = "ed25519")
    cx.argument::<JsValue>(0)
        .and_then(|v| {
            if v.is_a::<JsString>() {
                v.downcast::<JsString>().or_throw(&mut cx)
            } else {
                Ok(cx.string("ed25519"))
            }
        })
        .map(|v| v.value())
        // Assert that curve is one of the valid types: ['ed25519']
        .and_then(|curve| {
            if curve == "ed25519" {
                Ok(())
            } else {
                cx.throw_error("curve argument only supports: ed25519")
            }
        })
        // Second argument: seed
        .and_then(|_| {
            cx.argument_opt(1)
                .map(|v| {
                    if v.is_a::<JsBuffer>() {
                        v.downcast::<JsBuffer>().or_throw(&mut cx)
                    } else {
                        cx.throw_error("seed argument must be a buffer")
                    }
                })
                .transpose()
        })
        // Use seed if given, else, generate from random
        .map(|maybe_seed| match maybe_seed {
            Some(seed_buffer) => cx.borrow(&seed_buffer, |data| {
                let seed_bytes = data.as_slice::<u8>();
                let seed = Seed::from_slice(seed_bytes).unwrap();
                ed25519::keypair_from_seed(&seed)
            }),
            None => ed25519::gen_keypair(),
        })
        .and_then(|(pk, sk)| cx.compute_scoped(|mut cx2| make_keys_obj(&mut cx2, &pk, &sk)))
}

fn internal_create(path: &String) -> Result<(PublicKey, SecretKey), Error> {
    // TODO this path handling should be in ssb-keyfile
    let path = Path::new(path).to_path_buf();
    let _ = fs::create_dir_all(&path);
    let path = if path.is_dir() {
        path.join("secret")
    } else {
        path
    };
    if path.exists() {
        return Err(Error::new(
            ErrorKind::AlreadyExists,
            "refusing to overwrite",
        ));
    }

    // TODO these three steps should be in ssb-keyfile
    // Generate
    let (pk, sk) = ed25519::gen_keypair();

    // Render the file contents as a string
    let file_contents = ssb_keyfile::new_keyfile_string(&pk, &sk);

    // Write the file
    File::create(&path)
        .and_then(|mut file| file.write_all(file_contents.as_bytes()))
        .map(|_| (pk, sk))
}

struct CreateTask {
    argument: String,
}

impl Task for CreateTask {
    type Output = (PublicKey, SecretKey);
    type Error = Error;
    type JsEvent = JsObject;

    fn perform(&self) -> Result<(PublicKey, SecretKey), Error> {
        internal_create(&self.argument)
    }

    fn complete(
        self,
        mut cx: TaskContext,
        result: Result<(PublicKey, SecretKey), Error>,
    ) -> JsResult<JsObject> {
        result
            // TODO convert Error to Neon "Throw" with proper error info
            .or_else(|_| cx.throw_error("unable to create secret file"))
            .and_then(|(pk, sk)| cx.compute_scoped(|mut cx2| make_keys_obj(&mut cx2, &pk, &sk)))
    }
}

fn create(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    // TODO support all arguments (path, curve, isLegacy, cb)
    cx.argument::<JsValue>(0)
        .and_then(|v| {
            if v.is_a::<JsString>() {
                v.downcast::<JsString>().or_throw(&mut cx)
            } else {
                cx.throw_error("expected string as the first argument to `create`")
            }
        })
        .map(|v| v.value())
        .and_then(|path| {
            cx.argument::<JsValue>(1)
                .and_then(|f| {
                    if f.is_a::<JsFunction>() {
                        f.downcast::<JsFunction>().or_throw(&mut cx)
                    } else {
                        cx.throw_error("expected a callback function given to `create`")
                    }
                })
                .map(|cb| (path, cb))
        })
        .map(|(path, cb)| {
            let task = CreateTask { argument: path };
            task.schedule(cb);
            cx.undefined()
        })
}

fn create_sync(mut cx: FunctionContext) -> JsResult<JsObject> {
    // TODO support all arguments (path, curve, isLegacy)
    cx.argument::<JsValue>(0)
        .and_then(|v| {
            if v.is_a::<JsString>() {
                v.downcast::<JsString>().or_throw(&mut cx)
            } else {
                cx.throw_error("expected string as only argument to `loadSync`")
            }
        })
        .map(|v| v.value())
        .and_then(|path| {
            internal_create(&path).or_else(|_| cx.throw_error("unable to create secret file"))
        })
        .and_then(|(pk, sk)| cx.compute_scoped(|mut cx2| make_keys_obj(&mut cx2, &pk, &sk)))
}

fn internal_load(path: &String) -> Result<(PublicKey, SecretKey), SSBError> {
    // TODO this path handling should be in ssb-keyfile
    let path = Path::new(path).to_path_buf();
    let _ = fs::create_dir_all(&path);
    let path = if path.is_dir() {
        path.join("secret")
    } else {
        path
    };

    ssb_keyfile::load_keys_from_path(&path)
}

struct LoadTask {
    argument: String,
}

impl Task for LoadTask {
    type Output = (PublicKey, SecretKey);
    type Error = SSBError;
    type JsEvent = JsObject;

    fn perform(&self) -> Result<(PublicKey, SecretKey), SSBError> {
        internal_load(&self.argument)
    }

    fn complete(
        self,
        mut cx: TaskContext,
        result: Result<(PublicKey, SecretKey), SSBError>,
    ) -> JsResult<JsObject> {
        result
            // TODO convert SSBError to Neon "Throw" with proper error info
            .or_else(|_| cx.throw_error("unable to create secret file"))
            .and_then(|(pk, sk)| cx.compute_scoped(|mut cx2| make_keys_obj(&mut cx2, &pk, &sk)))
    }
}

fn load(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    cx.argument::<JsValue>(0)
        .and_then(|v| {
            if v.is_a::<JsString>() {
                v.downcast::<JsString>().or_throw(&mut cx)
            } else {
                cx.throw_error("expected string as the first argument to `load`")
            }
        })
        .map(|v| v.value())
        .and_then(|path| {
            cx.argument::<JsValue>(1)
                .and_then(|f| {
                    if f.is_a::<JsFunction>() {
                        f.downcast::<JsFunction>().or_throw(&mut cx)
                    } else {
                        cx.throw_error("expected a callback function given to `load`")
                    }
                })
                .map(|cb| (path, cb))
        })
        .map(|(path, cb)| {
            let task = LoadTask { argument: path };
            task.schedule(cb);
            cx.undefined()
        })
}

fn load_sync(mut cx: FunctionContext) -> JsResult<JsObject> {
    cx.argument::<JsValue>(0)
        .and_then(|v| {
            if v.is_a::<JsString>() {
                v.downcast::<JsString>().or_throw(&mut cx)
            } else {
                cx.throw_error("expected string as only argument to `loadSync`")
            }
        })
        .map(|v| v.value())
        .and_then(|path| {
            internal_load(&path).or_else(|_| cx.throw_error("unable to load secret file"))
        })
        .and_then(|(pk, sk)| cx.compute_scoped(|mut cx2| make_keys_obj(&mut cx2, &pk, &sk)))
}

register_module!(mut cx, {
    cx.export_function("generate", generate)?;
    cx.export_function("load", load)?;
    cx.export_function("loadSync", load_sync)?;
    cx.export_function("create", create)?;
    cx.export_function("createSync", create_sync)?;
    Ok(())
});
