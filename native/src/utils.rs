use arrayvec::ArrayVec;
use neon::handle::Managed;
use neon::object::This;
use neon::prelude::*;
use ssb_crypto::Keypair;
use std::fmt::Debug;

pub fn make_keys_obj<'a>(cx: &mut impl Context<'a>, kp: &Keypair) -> JsResult<'a, JsObject> {
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

pub fn call_builtin<'a, T>(
  cx: &mut impl Context<'a>,
  module: &str,
  name: &str,
  args: impl IntoIterator<Item = Handle<'a, JsValue>>,
) -> JsResult<'a, T>
where
  T: Value + Managed,
{
  let func = cx
    .global()
    .get(cx, module)?
    .downcast::<JsObject>()
    .or_throw(cx)?
    .get(cx, name)?
    .downcast::<JsFunction>()
    .or_throw(cx)?;

  let null = cx.null();
  func.call(cx, null, args)?.downcast::<T>().or_throw(cx)
}

// TODO publish to some neon-helpers library?
pub fn json_stringify<'a>(
  cx: &mut impl Context<'a>,
  args: impl IntoIterator<Item = Handle<'a, JsValue>>,
) -> JsResult<'a, JsString> {
  call_builtin(cx, "JSON", "stringify", args)
}

pub fn json_parse<'a>(
  cx: &mut impl Context<'a>,
  arg: Handle<'a, JsString>,
) -> JsResult<'a, JsObject> {
  call_builtin(cx, "JSON", "parse", ArrayVec::from([arg.upcast()]))
}

pub fn buffer_from<'a>(
  cx: &mut impl Context<'a>,
  args: impl IntoIterator<Item = Handle<'a, JsValue>>,
) -> JsResult<'a, JsBuffer> {
  call_builtin(cx, "Buffer", "from", args)
}

// TODO publish to some neon-helpers library?
pub fn clone_js_obj<'a>(
  cx: &mut impl Context<'a>,
  obj: Handle<JsObject>,
) -> JsResult<'a, JsObject> {
  let new_obj = cx.empty_object();
  let keys = obj.get_own_property_names(cx)?;
  for i in 0..keys.len() {
    let key = keys
      .get(cx, i)?
      .downcast::<JsString>()
      .or_throw(cx)?
      .value();
    let val = obj.get(cx, key.as_str())?;
    new_obj.set(cx, key.as_str(), val)?;
  }
  Ok(new_obj)
}

pub fn bytes_to_buffer<'a>(cx: &mut impl Context<'a>, bytes: &[u8]) -> JsResult<'a, JsBuffer> {
  let mut buffer = cx.buffer(bytes.len() as u32)?;
  cx.borrow_mut(&mut buffer, |data| {
    data.as_mut_slice().copy_from_slice(bytes)
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
