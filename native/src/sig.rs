use super::utils::{self, arg_as_string_or_field, OptionExt, StringExt};
use neon::prelude::*;

// TODO NetworkKey isn't a great name, I guess
use ssb_crypto::{Keypair, NetworkKey as AuthKey, PublicKey, Signature};

// sign: (keys: obj | string, hmac_key?: string, o: obj) => string
pub fn neon_sign_obj(mut cx: FunctionContext) -> JsResult<JsObject> {
  // FIXME: detect `curve` from keys.curve or from u.getTag and validate it
  let args_length = cx.len();
  if args_length < 2 {
    return cx.throw_error("signObj requires at least two arguments: (keys, msg)");
  }

  let keypair = {
    let private_str = arg_as_string_or_field(&mut cx, 0, "private").or_throw(
      &mut cx,
      "expected 1st argument to be the keys object or the private key string",
    )?;

    // println!("private_str {}", private_str);
    Keypair::from_base64(&private_str).ok_or_else(|| {
      cx.throw_error::<_, Keypair>("cannot decode private key bytes")
        .unwrap_err()
    })?
  };

  // TODO this is exactly the same inside neon_verify_obj, maybe could refactor
  let hmac_key = {
    if args_length == 3 {
      let array = cx.argument::<JsValue>(1).and_then(|v| {
        if v.is_a::<JsBuffer>() {
          let buf = v.downcast::<JsBuffer>().or_throw(&mut cx)?;
          let length = cx.borrow(&buf, |data| data.len());
          if length != 32 {
            return cx.throw_error("expected 2nd argument to be a 32-bytes Buffer");
          }
          let bytes = cx.borrow(&buf, |data| data.as_slice::<u8>());
          AuthKey::from_slice(bytes).or_throw(&mut cx, "hmac_key buffer must be 32 bytes")
        } else if v.is_a::<JsString>() {
          v.downcast::<JsString>()
            .or_throw(&mut cx)
            .map(|s| s.value())
            .and_then(|s| {
              AuthKey::from_base64(&s)
                .or_throw(&mut cx, "expected 2nd argument to be a base64 string")
            })
        } else {
          cx.throw_error("expected 2nd argument to be a Buffer for the hmac_key")
        }
      })?;
      Some(array)
    } else {
      None
    }
  };

  // TODO this is exactly the same inside neon_verify_obj, maybe could refactor
  let obj = {
    let index = if args_length == 2 { 1 } else { 2 };
    let ord = if args_length == 2 { "2nd" } else { "3rd" };
    cx.argument::<JsValue>(index).and_then(|v| {
      if v.is_a::<JsString>() {
        cx.throw_error(["expected ", ord, " arg to be object, was a string"].join(""))
      } else if v.is_a::<JsBuffer>() {
        cx.throw_error(["expected ", ord, " arg to be object, was a buffer"].join(""))
      } else if v.is_a::<JsArray>() {
        cx.throw_error(["expected ", ord, " arg to be object, was an array"].join(""))
      } else if v.is_a::<JsObject>() {
        v.downcast::<JsObject>().or_throw(&mut cx)
      } else {
        cx.throw_error(["expected ", ord, " arg to be a valid JS object"].join(""))
      }
    })?
  };

  let out_obj = cx
    .compute_scoped(|cx2| utils::clone_js_obj(cx2, obj))
    .or_else(|_| cx.throw_error("failed to create a clone of a javascript object"))?;

  let msg = {
    let null = cx.null();
    let args: Vec<Handle<JsValue>> = vec![obj.upcast(), null.upcast(), cx.number(2).upcast()];
    let stringified = cx
      .compute_scoped(|cx2| utils::json_stringify(cx2, args))
      .or_else(|_| cx.throw_error("failed to JSON.stringify the given `object` argument"))?
      .value();
    stringified.into_bytes()
  };

  // TODO this is exactly the same inside neon_verify_obj, maybe could refactor
  let sig = match hmac_key {
    None => keypair.sign(msg.as_slice()),
    Some(hmac_key) => {
      let tag = hmac_key.authenticate(msg.as_slice());
      keypair.sign(&tag.0)
    }
  };
  let signature = cx.string(sig.as_base64().with_suffix(".sig.ed25519"));

  out_obj
    .set(&mut cx, "signature", signature)
    .or_else(|_| cx.throw_error("failed to set the `signature` field in the object"))?;

  Ok(out_obj)
}

// verify: (keys: obj | string, hmac_key?: string, o: obj) => boolean
pub fn neon_verify_obj(mut cx: FunctionContext) -> JsResult<JsBoolean> {
  // FIXME: detect `curve` from keys.curve or from u.getTag and validate it
  let args_length = cx.len();
  if args_length < 2 {
    return cx.throw_error("verifyObj requires at least two arguments: (keys, msg)");
  }

  let public_key = {
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
          cx.throw_error(
            "expected `public` argument to be the keys object or the public key string",
          )
        }
      })
      .or_else(|_| cx.throw_error("failed to understand `private` argument"))?
      .value();
    // println!("public_str {}", public_str);

    PublicKey::from_base64(&public_str).or_throw(&mut cx, "cannot base64 decode the public key")?
  };

  // TODO this is exactly the same inside neon_verify_obj, maybe could refactor
  let hmac_key = {
    if args_length == 3 {
      let array = cx.argument::<JsValue>(1).and_then(|v| {
        if v.is_a::<JsBuffer>() {
          let buf = v.downcast::<JsBuffer>().or_throw(&mut cx)?;
          let length = cx.borrow(&buf, |data| data.len());
          if length != 32 {
            return cx.throw_error("expected 2nd argument to be a 32-bytes Buffer");
          }
          let bytes = cx.borrow(&buf, |data| data.as_slice::<u8>());
          AuthKey::from_slice(bytes).or_throw(&mut cx, "hmac_key buffer must be 32 bytes")
        } else if v.is_a::<JsString>() {
          v.downcast::<JsString>()
            .or_throw(&mut cx)
            .map(|s| s.value())
            .and_then(|s| {
              AuthKey::from_base64(&s)
                .or_throw(&mut cx, "expected 2nd argument to be a base64 string")
            })
        } else {
          cx.throw_error("expected 2nd argument to be a Buffer for the hmac_key")
        }
      })?;
      Some(array)
    } else {
      None
    }
  };

  let obj = {
    let index = if args_length == 2 { 1 } else { 2 };
    let ord = if args_length == 2 { "2nd" } else { "3rd" };
    cx.argument::<JsValue>(index).and_then(|v| {
      if v.is_a::<JsString>() {
        cx.throw_error(["expected ", ord, " arg to be object, was a string"].join(""))
      } else if v.is_a::<JsBuffer>() {
        cx.throw_error(["expected ", ord, " arg to be object, was a buffer"].join(""))
      } else if v.is_a::<JsArray>() {
        cx.throw_error(["expected ", ord, " arg to be object, was an array"].join(""))
      } else if v.is_a::<JsObject>() {
        v.downcast::<JsObject>().or_throw(&mut cx)
      } else {
        cx.throw_error(["expected ", ord, " arg to be a valid JS object"].join(""))
      }
    })?
  };

  let signature = {
    let sig = obj
      .get(&mut cx, "signature")
      .or_else(|_| cx.throw_error("obj.signature field is missing from obj"))?
      .downcast::<JsString>()
      .or_throw(&mut cx)
      .or_else(|_| cx.throw_error("obj.signature field is corrupted or not a string"))?
      .value();
    Signature::from_base64(&sig).or_throw(&mut cx, "unable to decode signature base64 string")?
  };

  let msg = {
    let verify_obj = cx
      .compute_scoped(|cx2| utils::clone_js_obj(cx2, obj))
      .or_else(|_| cx.throw_error("failed to create a clone of a javascript object"))?;
    let undef = cx.undefined();
    verify_obj
      .set(&mut cx, "signature", undef) // `delete` keyword in JS would be better
      .or_else(|_| cx.throw_error("failed to remove the `signature` field from the object"))?;

    let null = cx.null();
    let args: Vec<Handle<JsValue>> =
      vec![verify_obj.upcast(), null.upcast(), cx.number(2).upcast()];
    let stringified = cx
      .compute_scoped(|cx2| utils::json_stringify(cx2, args))
      .or_else(|_| cx.throw_error("failed to JSON.stringify the given verifying object"))?
      .value();
    stringified.into_bytes()
  };

  let passed = match hmac_key {
    None => public_key.verify(&signature, msg.as_slice()),
    Some(hmac_key) => {
      let tag = hmac_key.authenticate(msg.as_slice());
      public_key.verify(&signature, &tag.0)
    }
  };

  Ok(cx.boolean(passed))
}
