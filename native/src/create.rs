use super::utils::make_keys_obj;
use neon::prelude::*;
use sodiumoxide::crypto::sign::ed25519;
use sodiumoxide::crypto::sign::ed25519::{PublicKey, SecretKey};
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::io::{Error, ErrorKind};
use std::path::Path;

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
    let (pk, sk) = result
      // TODO convert Error to Neon "Throw" with proper error info
      .or_else(|_| cx.throw_error("unable to create secret file"))?;

    cx.compute_scoped(|mut cx2| make_keys_obj(&mut cx2, &pk, &sk))
  }
}

pub fn neon_create(mut cx: FunctionContext) -> JsResult<JsUndefined> {
  // TODO support all arguments (path, curve, isLegacy, cb)
  let path = cx
    .argument::<JsValue>(0)
    .and_then(|v| {
      if v.is_a::<JsString>() {
        v.downcast::<JsString>().or_throw(&mut cx)
      } else {
        cx.throw_error("expected string as the first argument to `create`")
      }
    })
    .or_else(|_| cx.throw_error("failed to understand the `path` argument"))?
    .value();

  let cb = cx
    .argument::<JsValue>(1)
    .and_then(|f| {
      if f.is_a::<JsFunction>() {
        f.downcast::<JsFunction>().or_throw(&mut cx)
      } else {
        cx.throw_error("expected a callback function given to `create`")
      }
    })
    .or_else(|_| cx.throw_error("failed to understand the `cb` argument"))?;

  let task = CreateTask { argument: path };
  task.schedule(cb);
  Ok(cx.undefined())
}

pub fn neon_create_sync(mut cx: FunctionContext) -> JsResult<JsObject> {
  // TODO support all arguments (path, curve, isLegacy)
  let path = cx
    .argument::<JsValue>(0)
    .and_then(|v| {
      if v.is_a::<JsString>() {
        v.downcast::<JsString>().or_throw(&mut cx)
      } else {
        cx.throw_error("expected string as only argument to `loadSync`")
      }
    })
    .or_else(|_| cx.throw_error("failed to understand the `path` argument"))?
    .value();

  let (pk, sk) =
    internal_create(&path).or_else(|_| cx.throw_error("unable to create secret file"))?;

  cx.compute_scoped(|mut cx2| make_keys_obj(&mut cx2, &pk, &sk))
}
