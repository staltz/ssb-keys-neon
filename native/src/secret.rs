use super::utils;
use neon::prelude::*;

use ssb_crypto::secretbox::{Hmac, Key, Nonce};

pub fn neon_secret_box(mut cx: FunctionContext) -> JsResult<JsValue> {
  let arg1 = cx.argument::<JsValue>(0)?;

  if arg1.is_a::<JsUndefined>() || arg1.is_a::<JsNull>() {
    return Ok(cx.undefined().upcast());
  }

  let mut plaintext = {
    let stringified = cx
      .compute_scoped(|cx2| utils::json_stringify(cx2, vec![arg1]))
      .or_else(|_| cx.throw_error("failed to JSON.stringify the given `msg` argument"))?
      .value();
    stringified.into_bytes()
  };

  let js_key = cx.argument::<JsValue>(1).and_then(|v| {
    if v.is_a::<JsBuffer>() {
      v.downcast::<JsBuffer>().or_throw(&mut cx)
    } else {
      cx.throw_error("2nd argument must be the key as a buffer")
    }
  })?;

  let key_bytes = cx.borrow(&js_key, |bytes| bytes.as_slice::<u8>());
  if key_bytes.len() < 32 {
    cx.throw_error("expected `secretbox` key to be at least 32 bytes")?;
  }
  let key = Key::from_slice(&key_bytes[0..32]).unwrap(); // infallible
  let nonce = Nonce::from_slice(&key_bytes[0..24]).unwrap(); // infallible

  let hmac = key.seal(&mut plaintext, &nonce);
  // `plaintext` now contains the cyphertext. "Attached" format begins with the hmac:
  plaintext.splice(0..0, hmac.0.iter().cloned());
  let buffer = cx.compute_scoped(|mut cx2| utils::bytes_to_buffer(&mut cx2, &plaintext))?;

  Ok(buffer.upcast())
}

pub fn neon_secret_unbox(mut cx: FunctionContext) -> JsResult<JsValue> {
  let arg1 = cx.argument::<JsValue>(0)?;

  if !arg1.is_a::<JsBuffer>() {
    return Ok(cx.undefined().upcast());
  }

  let buffer = arg1.downcast::<JsBuffer>().or_throw(&mut cx)?;
  let cyphertext = cx.borrow(&buffer, |bytes| bytes.as_slice::<u8>());

  let js_key = cx.argument::<JsValue>(1).and_then(|v| {
    if v.is_a::<JsBuffer>() {
      v.downcast::<JsBuffer>().or_throw(&mut cx)
    } else {
      cx.throw_error("2nd argument must be the key as a buffer")
    }
  })?;

  let key_bytes = cx.borrow(&js_key, |bytes| bytes.as_slice::<u8>());
  if key_bytes.len() < 32 {
    cx.throw_error("expected `secretbox` key to be at least 32 bytes")?;
  }
  let key = Key::from_slice(&key_bytes[0..32]).unwrap(); // infallible
  let nonce = Nonce::from_slice(&key_bytes[0..24]).unwrap(); // infallible

  let mut plaintext = vec![0; cyphertext.len() - Hmac::SIZE];

  if !key.open_attached_into(cyphertext, &nonce, &mut plaintext) {
    return cx.throw_error("failed to decrypt in secretUnbox");
  }
  let plaintext_str = String::from_utf8(plaintext);
  if plaintext_str.is_err() {
    return Ok(cx.undefined().upcast());
  }
  let plaintext_str = plaintext_str.unwrap();

  let out = {
    let args: Vec<Handle<JsString>> = vec![cx.string(plaintext_str)];
    cx.compute_scoped(|cx2| utils::json_parse(cx2, args))
  };
  if out.is_err() {
    return Ok(cx.undefined().upcast());
  }
  let out = out.unwrap();

  Ok(out.upcast())
}
