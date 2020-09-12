extern crate neon;

use neon::prelude::*;
use sodiumoxide::crypto::sign::ed25519::{PublicKey, SecretKey};

// TODO this should probably be public in ssb-keyfile
pub fn encode_key(bytes: &[u8]) -> String {
  let mut out = base64::encode_config(bytes, base64::STANDARD);
  out.push_str(".ed25519");
  out
}

// TODO this should probably be public in ssb-keyfile
pub fn decode_key(s: String) -> Result<Vec<u8>, base64::DecodeError> {
  let s = if s.starts_with("@") {
    String::from(s.trim_start_matches("@"))
  } else {
    s
  };
  let s = if s.ends_with(".ed25519") {
    String::from(s.trim_end_matches(".ed25519"))
  } else {
    s
  };
  base64::decode_config(&s, base64::STANDARD)
}

// TODO this should probably be public in ssb-keyfile
pub fn sig_encode_key(bytes: &[u8]) -> String {
  let mut out = base64::encode_config(bytes, base64::STANDARD);
  out.push_str(".sig.ed25519");
  out
}

// TODO this should probably be public in ssb-keyfile
pub fn sig_decode_key(s: String) -> Result<Vec<u8>, base64::DecodeError> {
  let s = if s.starts_with("@") {
    String::from(s.trim_start_matches("@"))
  } else {
    s
  };
  let s = if s.ends_with(".sig.ed25519") {
    String::from(s.trim_end_matches(".sig.ed25519"))
  } else {
    s
  };
  base64::decode_config(&s, base64::STANDARD)
}

pub fn make_keys_obj<'a, 'b, 'c>(
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
