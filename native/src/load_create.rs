use super::utils::{make_keys_obj, ContextExt};
use neon::prelude::*;

use ssb_crypto::Keypair;
use ssb_keyfile::KeyFileError as SSBError;

use std::fs::{self, File};
use std::io::prelude::*;
use std::io::{Error, ErrorKind};
use std::path::Path;

fn internal_create<P: AsRef<Path>>(path: P) -> Result<Keypair, Error> {
  // TODO this path handling should be in ssb-keyfile
  let mut path = path.as_ref().to_path_buf();
  let _ = fs::create_dir_all(&path);
  if path.is_dir() {
    path.push("secret");
  }
  if path.exists() {
    return Err(Error::new(
      ErrorKind::AlreadyExists,
      "refusing to overwrite",
    ));
  }

  // TODO these three steps should be in ssb-keyfile
  // Generate
  let keypair = Keypair::generate();

  // Render the file contents as a string
  let file_contents = ssb_keyfile::new_keyfile_string(&keypair);

  // Write the file
  File::create(&path).and_then(|mut file| file.write_all(file_contents.as_bytes()))?;
  Ok(keypair)
}

fn internal_load<P: AsRef<Path>>(path: P) -> Result<Keypair, SSBError> {
  // TODO this path handling should be in ssb-keyfile
  let _ = fs::create_dir_all(&path);
  if path.as_ref().is_dir() {
    ssb_keyfile::load_keys_from_path(path.as_ref().join("secret"))
  } else {
    ssb_keyfile::load_keys_from_path(path)
  }
}

struct CreateTask {
  argument: String,
}

impl Task for CreateTask {
  type Output = Keypair;
  type Error = Error;
  type JsEvent = JsObject;

  fn perform(&self) -> Result<Keypair, Error> {
    internal_create(&self.argument)
  }

  fn complete(self, mut cx: TaskContext, result: Result<Keypair, Error>) -> JsResult<JsObject> {
    let keypair = result.or_else(|e| cx.throw_error(e.to_string()))?;

    make_keys_obj(&mut cx, &keypair)
  }
}

struct LoadTask {
  argument: String,
}

impl Task for LoadTask {
  type Output = Keypair;
  type Error = SSBError;
  type JsEvent = JsObject;

  fn perform(&self) -> Result<Keypair, SSBError> {
    internal_load(&self.argument)
  }

  fn complete(self, mut cx: TaskContext, result: Result<Keypair, SSBError>) -> JsResult<JsObject> {
    let keypair = result.or_else(|e| cx.throw_error(e.to_string()))?;

    make_keys_obj(&mut cx, &keypair)
  }
}

struct LoadOrCreateTask {
  argument: String,
}

impl Task for LoadOrCreateTask {
  type Output = Keypair;
  type Error = Error;
  type JsEvent = JsObject;

  fn perform(&self) -> Result<Keypair, Error> {
    internal_load(&self.argument).or_else(|_| internal_create(&self.argument))
  }

  fn complete(self, mut cx: TaskContext, result: Result<Keypair, Error>) -> JsResult<JsObject> {
    let keypair = result.or_else(|e| cx.throw_error(e.to_string()))?;

    make_keys_obj(&mut cx, &keypair)
  }
}

pub fn neon_create(mut cx: FunctionContext) -> JsResult<JsUndefined> {
  // TODO support all arguments (path, curve, isLegacy, cb)
  let path = cx
    .arg_as::<JsString>(0, "expected string as the first argument to `create`")?
    .value();

  let cb = cx.arg_as::<JsFunction>(1, "expected a callback function given to `create`")?;
  let task = CreateTask { argument: path };
  task.schedule(cb);
  Ok(cx.undefined())
}

pub fn neon_create_sync(mut cx: FunctionContext) -> JsResult<JsObject> {
  // TODO support all arguments (path, curve, isLegacy)
  let path = cx
    .arg_as::<JsString>(0, "expected string as only argument to `loadSync`")?
    .value();

  let keypair = internal_create(&path).or_else(|e| cx.throw_error(e.to_string()))?;

  make_keys_obj(&mut cx, &keypair)
}

pub fn neon_load(mut cx: FunctionContext) -> JsResult<JsUndefined> {
  let path = cx
    .arg_as::<JsString>(0, "expected string as the first argument to `load`")?
    .value();

  let cb = cx.arg_as::<JsFunction>(1, "expected a callback function given to `load`")?;

  let task = LoadTask { argument: path };
  task.schedule(cb);
  Ok(cx.undefined())
}

pub fn neon_load_sync(mut cx: FunctionContext) -> JsResult<JsObject> {
  let path = cx
    .arg_as::<JsString>(0, "expected string as only argument to `loadSync`")?
    .value();

  let keypair = internal_load(&path).or_else(|e| cx.throw_error(e.to_string()))?;

  make_keys_obj(&mut cx, &keypair)
}

pub fn neon_load_or_create(mut cx: FunctionContext) -> JsResult<JsUndefined> {
  let path = cx
    .arg_as::<JsString>(0, "expected string as the first argument to `loadOrCreate`")?
    .value();

  let cb =
    cx.arg_as::<JsFunction>(1, "expected a callback function given to `loadOrCreate`")?;

  let task = LoadOrCreateTask { argument: path };
  task.schedule(cb);
  Ok(cx.undefined())
}

pub fn neon_load_or_create_sync(mut cx: FunctionContext) -> JsResult<JsObject> {
  let path = cx
    .arg_as::<JsString>(0, "expected string as only argument to `loadOrCreateSync`")?
    .value();

  let keypair = internal_load(&path)
    .or_else(|_| internal_create(&path))
    .or_else(|e| cx.throw_error(e.to_string()))?;

  make_keys_obj(&mut cx, &keypair)
}
