use super::utils::make_keys_obj;
use neon::prelude::*;
use sodiumoxide::crypto::sign::ed25519::{PublicKey, SecretKey};
use ssb_keyfile::Error as SSBError;
use std::fs;
use std::path::Path;

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
    let (pk, sk) = result
      // TODO convert SSBError to Neon "Throw" with proper error info
      .or_else(|_| cx.throw_error("unable to create secret file"))?;

    cx.compute_scoped(|mut cx2| make_keys_obj(&mut cx2, &pk, &sk))
  }
}

pub fn neon_load(mut cx: FunctionContext) -> JsResult<JsUndefined> {
  let path = cx
    .argument::<JsValue>(0)
    .and_then(|v| {
      if v.is_a::<JsString>() {
        v.downcast::<JsString>().or_throw(&mut cx)
      } else {
        cx.throw_error("expected string as the first argument to `load`")
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
        cx.throw_error("expected a callback function given to `load`")
      }
    })
    .or_else(|_| cx.throw_error("failed to understand the `cb` argument"))?;

  let task = LoadTask { argument: path };
  task.schedule(cb);
  Ok(cx.undefined())
}

pub fn neon_load_sync(mut cx: FunctionContext) -> JsResult<JsObject> {
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

  let (pk, sk) = internal_load(&path).or_else(|_| cx.throw_error("unable to load secret file"))?;

  cx.compute_scoped(|mut cx2| make_keys_obj(&mut cx2, &pk, &sk))
}
