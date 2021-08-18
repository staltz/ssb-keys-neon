use super::utils::{
  self, get_string_or_field, type_name, ContextExt, HandleExt, OptionExt, StringExt, ValueExt,
};
use arrayvec::ArrayVec;
use neon::prelude::*;

// TODO NetworkKey isn't a great name, I guess
use ssb_crypto::{Keypair, NetworkKey as AuthKey, PublicKey, Signature};

// sign: (keys: obj | string, hmac_key: Buffer | string, str: string) => string
pub fn neon_sign(mut cx: FunctionContext) -> JsResult<JsString> {
  // FIXME: detect `curve` from keys.curve or from u.getTag and validate it
  let argc = cx.len();
  if argc < 2 {
    return cx.throw_error("sign requires at least two arguments: (keys, msg)");
  }

  let keypair = {
    let arg = cx.argument(0)?;
    let private_str = get_string_or_field(&mut cx, arg, "private").or_throw(
      &mut cx,
      "expected 1st argument to be the keys object or the private key string",
    )?;

    Keypair::from_base64(&private_str).or_throw(&mut cx, "cannot decode private key bytes")?
  };

  // TODO this is exactly the same inside neon_verify_obj, maybe could refactor
  let hmac_key = {
    if argc == 3 && cx.argument::<JsValue>(1)?.is_truthy(&mut cx) {
      let authkey = cx.argument::<JsValue>(1).and_then(|v| {
        if let Some(buf) = v.try_downcast::<JsBuffer>() {
          let bytes = cx.borrow(&buf, |data| data.as_slice::<u8>());
          AuthKey::from_slice(bytes).or_throw(&mut cx, "hmac_key buffer must be 32 bytes")
        } else if let Some(s) = v.try_downcast::<JsString>() {
          AuthKey::from_base64(&s.value())
            .or_throw(&mut cx, "expected 2nd argument to be a base64 string")
        } else {
          cx.throw_error("expected 2nd argument to be a Buffer for the hmac_key")
        }
      })?;
      Some(authkey)
    } else {
      None
    }
  };

  let msg = cx
    .arg_as::<JsString>(argc - 1, "expected 2nd arg to be a plaintext string")?
    .value()
    .into_bytes();

  let sig = match hmac_key {
    None => keypair.sign(msg.as_slice()),
    Some(hmac_key) => {
      let tag = hmac_key.authenticate(msg.as_slice());
      keypair.sign(&tag.0)
    }
  };

  let signature = cx.string(sig.as_base64().with_suffix(".sig.ed25519"));

  Ok(signature)
}

// verify: (keys: obj | string, signature: string, hmac_key, str: string) => boolean
pub fn neon_verify(mut cx: FunctionContext) -> JsResult<JsBoolean> {
  // FIXME: detect `curve` from keys.curve or from u.getTag and validate it
  let argc = cx.len();
  if argc < 3 {
    return cx.throw_error("verify requires at least two arguments: (keys, msg)");
  }

  let public_key = {
    let arg = cx.argument(0)?;
    let public_str = get_string_or_field(&mut cx, arg, "public").or_throw(
      &mut cx,
      "expected `public` argument to be the keys object or the public key string",
    )?;
    PublicKey::from_base64(&public_str).or_throw(&mut cx, "cannot base64 decode the public key")?
  };

  let signature = {
    let mut sig = cx
      .arg_as::<JsString>(1, "expected 2nd arg to be a signature string")?
      .value();
    match sig.rfind(".sig.ed25519") {
      None => return cx.throw_error("Invalid signature string, is missing dot suffix"),
      Some(dot_index) => sig.truncate(dot_index)
    };
    Signature::from_base64(&sig).or_throw(&mut cx, "unable to decode signature base64 string")?
  };

  // TODO this is almost the same inside neon_verify_obj, maybe could refactor
  let hmac_key = {
    if argc == 4 && cx.argument::<JsValue>(2)?.is_truthy(&mut cx) {
      let authkey = cx.argument::<JsValue>(2).and_then(|v| {
        if let Some(buf) = v.try_downcast::<JsBuffer>() {
          let bytes = cx.borrow(&buf, |data| data.as_slice::<u8>());
          AuthKey::from_slice(bytes).or_throw(&mut cx, "hmac_key buffer must be 32 bytes")
        } else if let Some(s) = v.try_downcast::<JsString>() {
          AuthKey::from_base64(&s.value())
            .or_throw(&mut cx, "expected 3rd argument to be a base64 string")
        } else {
          cx.throw_error("expected 3rd argument to be a Buffer for the hmac_key")
        }
      })?;
      Some(authkey)
    } else {
      None
    }
  };

  let msg = cx
    .arg_as::<JsString>(argc - 1 , "expected last arg to be a plaintext string")?
    .value();

  let passed = match hmac_key {
    None => public_key.verify(&signature, msg.into_bytes().as_slice()),
    Some(hmac_key) => {
      let tag = hmac_key.authenticate(msg.into_bytes().as_slice());
      public_key.verify(&signature, &tag.0)
    }
  };

  Ok(cx.boolean(passed))
}

// sign: (keys: obj | string, hmac_key?: string, o: obj) => string
pub fn neon_sign_obj(mut cx: FunctionContext) -> JsResult<JsObject> {
  // FIXME: detect `curve` from keys.curve or from u.getTag and validate it
  let argc = cx.len();
  if argc < 2 {
    return cx.throw_error("signObj requires at least two arguments: (keys, msg)");
  }

  let keypair = {
    let arg = cx.argument(0)?;
    let private_str = get_string_or_field(&mut cx, arg, "private").or_throw(
      &mut cx,
      "expected 1st argument to be the keys object or the private key string",
    )?;

    Keypair::from_base64(&private_str).or_throw(&mut cx, "cannot decode private key bytes")?
  };

  // TODO this is exactly the same inside neon_verify_obj, maybe could refactor
  let hmac_key = {
    if argc == 3 && cx.argument::<JsValue>(1)?.is_truthy(&mut cx) {
      let authkey = cx.argument::<JsValue>(1).and_then(|v| {
        if let Some(buf) = v.try_downcast::<JsBuffer>() {
          let bytes = cx.borrow(&buf, |data| data.as_slice::<u8>());
          AuthKey::from_slice(bytes).or_throw(&mut cx, "hmac_key buffer must be 32 bytes")
        } else if let Some(s) = v.try_downcast::<JsString>() {
          AuthKey::from_base64(&s.value())
            .or_throw(&mut cx, "expected 2nd argument to be a base64 string")
        } else {
          cx.throw_error("expected 2nd argument to be a Buffer for the hmac_key")
        }
      })?;
      Some(authkey)
    } else {
      None
    }
  };

  // TODO this is exactly the same inside neon_verify_obj, maybe could refactor
  let out_obj = {
    let (index, ord) = if argc == 2 { (1, "2nd") } else { (2, "3rd") };
    let v = cx.argument::<JsValue>(index)?;
    let obj = if v.is_a::<JsObject>() {
      Ok(v.downcast::<JsObject>().unwrap())
    } else {
      cx.throw_error(format!(
        "expected {} arg to be object, was a {}",
        ord,
        type_name(&v)
      ))
    }?;
    utils::clone_js_obj(&mut cx, obj)?
  };

  let msg = {
    let null = cx.null();
    let args = ArrayVec::from([out_obj.upcast(), null.upcast(), cx.number(2).upcast()]);
    utils::json_stringify(&mut cx, args)?.value().into_bytes()
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
  let argc = cx.len();
  if argc < 2 {
    return cx.throw_error("verifyObj requires at least two arguments: (keys, msg)");
  }

  let public_key = {
    let arg = cx.argument(0)?;
    let public_str = get_string_or_field(&mut cx, arg, "public").or_throw(
      &mut cx,
      "expected `public` argument to be the keys object or the public key string",
    )?;
    PublicKey::from_base64(&public_str).or_throw(&mut cx, "cannot base64 decode the public key")?
  };

  let hmac_key = {
    if argc == 3 && cx.argument::<JsValue>(1)?.is_truthy(&mut cx) {
      let authkey = cx.argument::<JsValue>(1).and_then(|v| {
        if let Some(buf) = v.try_downcast::<JsBuffer>() {
          let bytes = cx.borrow(&buf, |data| data.as_slice::<u8>());
          AuthKey::from_slice(bytes).or_throw(&mut cx, "hmac_key buffer must be 32 bytes")
        } else if let Some(s) = v.try_downcast::<JsString>() {
          AuthKey::from_base64(&s.value())
            .or_throw(&mut cx, "expected 2nd argument to be a base64 string")
        } else {
          cx.throw_error("expected 2nd argument to be a Buffer for the hmac_key")
        }
      })?;
      Some(authkey)
    } else {
      None
    }
  };

  let verify_obj = {
    let (index, ord) = if argc == 2 { (1, "2nd") } else { (2, "3rd") };
    let v = cx.argument::<JsValue>(index)?;
    let obj = if v.is_a::<JsObject>() {
      Ok(v.downcast::<JsObject>().unwrap())
    } else {
      cx.throw_error(format!(
        "expected {} arg to be object, was a {}",
        ord,
        type_name(&v)
      ))
    }?;
    utils::clone_js_obj(&mut cx, obj)?
  };

  let signature = {
    let mut sig = verify_obj
      .get(&mut cx, "signature")
      .or_else(|_| cx.throw_error("obj.signature field is missing from obj"))?
      .downcast::<JsString>()
      .or_throw(&mut cx)
      .or_else(|_| cx.throw_error("obj.signature field is corrupted or not a string"))?
      .value();
    match sig.rfind(".sig.ed25519") {
      None => return cx.throw_error("Invalid signature string, is missing dot suffix"),
      Some(dot_index) => sig.truncate(dot_index)
    };
    Signature::from_base64(&sig).or_throw(&mut cx, "unable to decode signature base64 string")?
  };

  let msg = {
    let undef = cx.undefined();
    verify_obj
      .set(&mut cx, "signature", undef) // `delete` keyword in JS would be better
      .or_else(|_| cx.throw_error("failed to remove the `signature` field from the object"))?;

    let args = ArrayVec::from([
      verify_obj.upcast(),
      cx.null().upcast(),
      cx.number(2).upcast(),
    ]);
    utils::json_stringify(&mut cx, args)?.value().into_bytes()
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
