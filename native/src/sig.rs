use super::utils;
use neon::prelude::*;
use sodiumoxide::crypto::sign::ed25519;

// sign: (keys: obj | string, hmac_key?: string, o: obj) => string
pub fn neon_sign_obj(mut cx: FunctionContext) -> JsResult<JsObject> {
  // FIXME: support hmac_key
  let args_length = cx.len();
  if args_length < 2 {
    return cx.throw_error("signObj requires at least two arguments: (keys, msg)");
  }

  let private_key = cx
    .argument::<JsValue>(0)
    .and_then(|v| {
      if v.is_a::<JsString>() {
        v.downcast::<JsString>().or_throw(&mut cx)
      } else if v.is_a::<JsObject>() {
        v.downcast::<JsObject>()
          .or_throw(&mut cx)?
          .get(&mut cx, "private")?
          .downcast::<JsString>()
          .or_throw(&mut cx)
      } else {
        cx.throw_error(
          "expected `private` argument to be the keys object or the private key string",
        )
      }
    })
    .or_else(|_| cx.throw_error("failed to understand `private` argument"))?
    .value();
  // println!("private_str {}", private_str);
  let private_key = utils::decode_key(private_key)
    .or_else(|_| cx.throw_error("cannot base64 decode the private key given to `signObj`"))?;
  let private_key = private_key.as_slice();
  let private_key = ed25519::SecretKey::from_slice(&private_key)
    .ok_or(0)
    .or_else(|_| cx.throw_error("cannot decode private key bytes"))?;

  let obj = cx
    .argument::<JsObject>(1)
    .or_else(|_| cx.throw_error("expected `object` argument to be a valid JS object"))?;
  let out_obj = cx
    .compute_scoped(|cx2| utils::clone_js_obj(cx2, obj))
    .or_else(|_| cx.throw_error("failed to create a clone of a javascript object"))?;

  let null = cx.null();
  let args: Vec<Handle<JsValue>> = vec![obj.upcast(), null.upcast(), cx.number(2).upcast()];
  let msg = cx
    .compute_scoped(|cx2| utils::json_stringify(cx2, args))
    .or_else(|_| cx.throw_error("failed to JSON.stringify the given `object` argument"))?
    .value();
  let msg = msg.into_bytes();
  let msg = msg.as_slice();

  // FIXME: detect `curve` from keys.curve or from u.getTag and validate it

  let ed25519::Signature(sig) = ed25519::sign_detached(msg, &private_key);
  let signature = utils::sig_encode_key(&sig);

  // println!("sig: {}", signature_string);
  let signature = cx.string(signature);
  out_obj
    .set(&mut cx, "signature", signature)
    .or_else(|_| cx.throw_error("failed to set the `signature` field in the object"))?;

  Ok(out_obj)
}

// verify: (keys: obj | string, hmac_key?: string, o: obj) => boolean
pub fn neon_verify_obj(mut cx: FunctionContext) -> JsResult<JsBoolean> {
  // FIXME: support hmac_keys
  let args_length = cx.len();
  if args_length < 2 {
    return cx.throw_error("verifyObj requires at least two arguments: (keys, msg)");
  }

  let public_str = cx
    .argument::<JsValue>(0)
    .and_then(|v| {
      if v.is_a::<JsString>() {
        v.downcast::<JsString>().or_throw(&mut cx)
      } else if v.is_a::<JsObject>() {
        v.downcast::<JsObject>()
          .or_throw(&mut cx)?
          .get(&mut cx, "public")?
          .downcast::<JsString>()
          .or_throw(&mut cx)
      } else {
        cx.throw_error("expected `public` argument to be the keys object or the public key string")
      }
    })
    .or_else(|_| cx.throw_error("failed to understand `private` argument"))?
    .value();
  // println!("public_str {}", public_str);
  let public_key = utils::decode_key(public_str)
    .or_else(|_| cx.throw_error("cannot base64 decode the public key"))?;
  let public_key = public_key.as_slice();
  let public_key = ed25519::PublicKey::from_slice(&public_key)
    .ok_or(0)
    .or_else(|_| cx.throw_error("cannot decode public key bytes"))?;

  let obj = cx
    .argument::<JsObject>(1)
    .or_else(|_| cx.throw_error("expected `object` argument to be a valid JS object"))?;
  let sig = obj
    .get(&mut cx, "signature")
    .or_else(|_| cx.throw_error("obj.signature field is missing from obj"))?
    .downcast::<JsString>()
    .or_throw(&mut cx)
    .or_else(|_| cx.throw_error("obj.signature field is corrupted or not a string"))?
    .value();
  let sig = utils::sig_decode_key(sig)
    .or_else(|_| cx.throw_error("unable to decode signature base64 string"))?;
  let sig = ed25519::Signature::from_slice(&sig)
    .ok_or(0)
    .or_else(|_| cx.throw_error("cannot decode signature bytes"))?;

  let verify_obj = cx
    .compute_scoped(|cx2| utils::clone_js_obj(cx2, obj))
    .or_else(|_| cx.throw_error("failed to create a clone of a javascript object"))?;
  let undef = cx.undefined();
  verify_obj
    .set(&mut cx, "signature", undef) // `delete` keyword in JS would be better
    .or_else(|_| cx.throw_error("failed to remove the `signature` field from the object"))?;
  let null = cx.null();
  let args: Vec<Handle<JsValue>> = vec![verify_obj.upcast(), null.upcast(), cx.number(2).upcast()];
  let msg = cx
    .compute_scoped(|cx2| utils::json_stringify(cx2, args))
    .or_else(|_| cx.throw_error("failed to JSON.stringify the given verifying object"))?
    .value();
  let msg = msg.into_bytes();
  let msg = msg.as_slice();

  let passed = ed25519::verify_detached(&sig, msg, &public_key);
  Ok(cx.boolean(passed))
}
