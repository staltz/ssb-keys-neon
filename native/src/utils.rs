use arrayvec::ArrayVec;
use neon::handle::Managed;
use neon::object::This;
use neon::prelude::*;
use ssb_crypto::Keypair;

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
  field: &str,
) -> Option<String> {
  let v = cx.argument(arg).ok()?;
  get_string_or_field(cx, v, field)
}

pub fn get_string_or_field<'a, T: This>(
  cx: &mut CallContext<'a, T>,
  v: Handle<JsValue>,
  field: &str,
) -> Option<String> {
  if let Some(s) = v.try_downcast::<JsString>() {
    Some(s.value())
  } else if let Some(obj) = v.try_downcast::<JsObject>() {
    let f = obj.get(cx, field).ok()?;
    let s = f.try_downcast::<JsString>()?;
    Some(s.value())
  } else {
    None
  }
}

pub fn type_name(v: &Handle<JsValue>) -> &'static str {
  if v.is_a::<JsArray>() {
    "array"
  } else if v.is_a::<JsArrayBuffer>() {
    "array buffer"
  } else if v.is_a::<JsBoolean>() {
    "boolean"
  } else if v.is_a::<JsBuffer>() {
    "buffer"
  } else if v.is_a::<JsError>() {
    "error"
  } else if v.is_a::<JsNull>() {
    "null"
  } else if v.is_a::<JsNumber>() {
    "number"
  } else if v.is_a::<JsObject>() {
    "object"
  } else if v.is_a::<JsString>() {
    "string"
  } else if v.is_a::<JsUndefined>() {
    "undefined"
  } else {
    "something else" // :)
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
  fn or_throw<'a, S: AsRef<str>>(
    self,
    cx: &mut impl Context<'a>,
    msg: S,
  ) -> Result<T, neon::result::Throw>;
}

impl<T> OptionExt<T> for Option<T> {
  fn or_throw<'a, S: AsRef<str>>(
    self,
    cx: &mut impl Context<'a>,
    msg: S,
  ) -> Result<T, neon::result::Throw> {
    // Result<T, _>::unwrap_err and expect_err require T: Debug, which JsArray doesn't impl
    self.ok_or_else(|| cx.throw_error::<_, T>(msg).err().unwrap())
  }
}

// `if let Ok(s) = v.downcast::<JsString>() { ... }`
// can be used with zero cost (aside from the type tag check)
// when this PR is merged: https://github.com/neon-bindings/neon/pull/606
//
// In the meantime, we'll use this:
pub trait HandleExt {
  fn try_downcast<U: Value>(&self) -> Option<Handle<U>>;
}
impl<'a, T: Value> HandleExt for Handle<'a, T> {
  fn try_downcast<U: Value>(&self) -> Option<Handle<U>> {
    if self.is_a::<U>() {
      Some(self.downcast::<U>().unwrap())
    } else {
      None
    }
  }
}

pub trait ValueExt {
  fn is_truthy<'a, C: Context<'a>>(&self, cx: &mut C) -> bool;
}

impl<T: Value + Managed> ValueExt for T {
  fn is_truthy<'a, C: Context<'a>>(&self, cx: &mut C) -> bool {
    let global = cx.global();
    let boolean = global
      .get(cx, "Boolean")
      .unwrap()
      .downcast::<JsFunction>()
      .unwrap();
    let args = ArrayVec::from([self.as_value(cx)]);
    let b = boolean
      .call(cx, global, args)
      .unwrap()
      .downcast::<JsBoolean>()
      .unwrap();
    b.value()
  }
}
