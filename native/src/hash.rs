use super::utils;
use neon::prelude::*;
use sodiumoxide::crypto::hash::sha256;

pub fn neon_hash(mut cx: FunctionContext) -> JsResult<JsString> {
  let args_length = cx.len();

  let data = {
    cx.argument::<JsValue>(0).and_then(|v| {
      if v.is_a::<JsString>() || v.is_a::<JsBuffer>() {
        Ok(v)
      } else {
        cx.throw_error("expected 1st argument to `hash` to be a string or buffer")
      }
    })
  }?;

  let enc = {
    let fallback = cx.string("binary").upcast::<JsValue>();
    if args_length == 2 {
      cx.argument::<JsValue>(1).and_then(|v| {
        if v.is_a::<JsString>() {
          Ok(v)
        } else if v.is_a::<JsNull>() || v.is_a::<JsUndefined>() {
          Ok(fallback)
        } else {
          cx.throw_error("expected encoding string as the 2nd argument to `hash`")
        }
      })
    } else {
      Ok(fallback)
    }
  }?;

  let data_buffer = {
    let args: Vec<Handle<JsValue>> = vec![data, enc];
    cx.compute_scoped(|cx2| utils::buffer_from(cx2, args))
  }?;
  let data_bytes = cx.borrow(&data_buffer, |bytes| bytes.as_slice::<u8>());

  let hashed = sha256::hash(data_bytes);

  let mut out = base64::encode_config(&hashed, base64::STANDARD);
  out.push_str(".sha256");

  Ok(cx.string(out))
}