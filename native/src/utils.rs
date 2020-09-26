extern crate neon;

use neon::object::This;
use neon::prelude::*;
use ssb_crypto::Keypair;
use std::fmt::Debug;

pub fn make_keys_obj<'a, 'b, 'c>(
  cx: &mut ComputeContext<'b, 'c>,
  kp: &'a Keypair,
) -> JsResult<'b, JsObject> {
  let keys_obj = JsObject::new(cx);
  let curve_val = cx.string("ed25519");
  let id_val = cx.string(kp.public.as_base64().wrap('@', ".ed25519"));
  let private_val = cx.string(kp.as_base64().with_suffix(".ed25519"));
  let public_val = cx.string(kp.public.as_base64().with_suffix(".ed25519"));
  keys_obj.set(cx, "curve", curve_val)?;
  keys_obj.set(cx, "id", id_val)?;
  keys_obj.set(cx, "private", private_val)?;
  keys_obj.set(cx, "public", public_val)?;
  Ok(keys_obj)
}

// TODO publish to some neon-helpers library?
pub fn json_stringify<'a, 'b>(
  mut cx: ComputeContext<'a, 'b>,
  args: Vec<Handle<JsValue>>,
) -> JsResult<'a, JsString> {
  let stringify = cx
    .global()
    .get(&mut cx, "JSON")?
    .downcast::<JsObject>()
    .or_throw(&mut cx)?
    .get(&mut cx, "stringify")?
    .downcast::<JsFunction>()
    .or_throw(&mut cx)?;
  let null = cx.null();
  stringify
    .call(&mut cx, null, args)?
    .downcast::<JsString>()
    .or_throw(&mut cx)
}

// TODO publish to some neon-helpers library?
pub fn json_parse<'a, 'b>(
  mut cx: ComputeContext<'a, 'b>,
  args: Vec<Handle<JsString>>,
) -> JsResult<'a, JsObject> {
  let parse = cx
    .global()
    .get(&mut cx, "JSON")?
    .downcast::<JsObject>()
    .or_throw(&mut cx)?
    .get(&mut cx, "parse")?
    .downcast::<JsFunction>()
    .or_throw(&mut cx)?;
  let null = cx.null();
  parse
    .call(&mut cx, null, args)?
    .downcast::<JsObject>()
    .or_throw(&mut cx)
}

// TODO publish to some neon-helpers library?
pub fn buffer_from<'a, 'b>(
  mut cx: ComputeContext<'a, 'b>,
  args: Vec<Handle<JsValue>>,
) -> JsResult<'a, JsBuffer> {
  let from = cx
    .global()
    .get(&mut cx, "Buffer")?
    .downcast::<JsObject>()
    .or_throw(&mut cx)?
    .get(&mut cx, "from")?
    .downcast::<JsFunction>()
    .or_throw(&mut cx)?;
  let null = cx.null();
  from
    .call(&mut cx, null, args)?
    .downcast::<JsBuffer>()
    .or_throw(&mut cx)
}

// TODO publish to some neon-helpers library?
pub fn clone_js_obj<'a, 'b>(
  mut cx: ComputeContext<'a, 'b>,
  obj: Handle<JsObject>,
) -> JsResult<'a, JsObject> {
  let new_obj = cx.empty_object();
  let keys = obj.get_own_property_names(&mut cx)?;
  for i in 0..keys.len() {
    let key = keys
      .get(&mut cx, i)?
      .downcast::<JsString>()
      .or_throw(&mut cx)?
      .value();
    let val = obj.get(&mut cx, key.as_str())?;
    new_obj.set(&mut cx, key.as_str(), val)?;
  }
  Ok(new_obj)
}

pub fn bytes_to_buffer<'a, 'b, 'c>(
  cx: &mut ComputeContext<'b, 'c>,
  bytes: &[u8],
) -> JsResult<'b, JsBuffer> {
  let length = bytes.len() as usize;
  let mut buffer = cx.buffer(bytes.len() as u32)?;
  cx.borrow_mut(&mut buffer, |data| {
    let slice = data.as_mut_slice();
    for i in 0..length {
      slice[i] = bytes[i];
    }
  });
  Ok(buffer)
}

pub fn arg_as_string_or_field<'a, T: This>(
  cx: &mut CallContext<'a, T>,
  arg: i32,
  field: &'static str,
) -> Option<String> {
  let v = cx.argument::<JsValue>(arg).ok()?;

  if let Ok(s) = v.downcast::<JsString>() {
    Some(s.value())
  } else if let Ok(obj) = v.downcast::<JsObject>() {
    let s = obj.get(cx, field).ok()?.downcast::<JsString>().ok()?;

    Some(s.value())
  } else {
    None
  }
}

pub trait StringExt {
  fn with_suffix(self, s: &str) -> Self;
  fn wrap(self, prefix: char, suffix: &str) -> Self;
}

impl StringExt for String {
  fn with_suffix(mut self, s: &str) -> Self {
    self.push_str(s);
    self
  }
  fn wrap(mut self, prefix: char, suffix: &str) -> Self {
    self.insert(0, prefix);
    self.push_str(suffix);
    self
  }
}

pub trait OptionExt<T> {
  fn or_throw<'a>(
    self,
    cx: &mut impl Context<'a>,
    msg: &'static str,
  ) -> Result<T, neon::result::Throw>;
}

impl<T: Debug> OptionExt<T> for Option<T> {
  fn or_throw<'a>(
    self,
    cx: &mut impl Context<'a>,
    msg: &'static str,
  ) -> Result<T, neon::result::Throw> {
    self.ok_or_else(|| cx.throw_error::<_, T>(msg).unwrap_err())
  }
}
