use super::utils;
use neon::prelude::*;
use neon::result::Throw;
use sodiumoxide::crypto::sign::ed25519;
use sodiumoxide::crypto::sign::PublicKey;

pub fn neon_box(mut cx: FunctionContext) -> JsResult<JsString> {
  let msg = {
    let arg1 = cx.argument::<JsValue>(0)?;
    let stringified = cx
      .compute_scoped(|cx2| utils::json_stringify(cx2, vec![arg1]))
      .or_else(|_| cx.throw_error("failed to JSON.stringify the given `msg` argument"))?
      .value();
    stringified.into_bytes()
  };

  let recps: Vec<PublicKey> = cx
    .argument::<JsValue>(1)
    .and_then(|v| {
      if v.is_a::<JsArray>() {
        v.downcast::<JsArray>().or_throw(&mut cx)?.to_vec(&mut cx)
      } else {
        cx.throw_error("expected 2nd argument to be an array of recipients")
      }
    })?
    .iter()
    .flat_map(|recp| {
      let public_key: Result<ed25519::PublicKey, Throw> = {
        let public_str = if recp.is_a::<JsObject>() {
          recp
            .downcast::<JsObject>()
            .or_throw(&mut cx)?
            .get(&mut cx, "public")?
            .downcast::<JsString>()
            .or_throw(&mut cx)?
            .value()
        } else {
          recp.downcast::<JsString>().or_throw(&mut cx)?.value()
        };
        let vec = utils::decode_key(public_str)
          .or_else(|_| cx.throw_error("cannot base64 decode the public key"))?;
        let key = ed25519::PublicKey::from_slice(&vec)
          .ok_or(0)
          .or_else(|_| cx.throw_error("cannot decode public key bytes"))?;
        Ok(key)
      };
      public_key
    })
    .collect();

  let multiboxed = private_box::encrypt(msg.as_slice(), recps.as_slice());
  let mut out = base64::encode_config(multiboxed.as_slice(), base64::STANDARD);
  out.push_str(".box");

  Ok(cx.string(out))
}

pub fn neon_unbox(mut cx: FunctionContext) -> JsResult<JsValue> {
  let cyphertext = {
    let ctxt_str = cx
      .argument::<JsValue>(0)
      .and_then(|v| {
        if v.is_a::<JsString>() {
          v.downcast::<JsString>().or_throw(&mut cx)
        } else {
          cx.throw_error("expected 1st argument to be the cyphertext as a string")
        }
      })?
      .value();
    let ctxt_str = if ctxt_str.ends_with(".box") {
      String::from(ctxt_str.trim_end_matches(".box"))
    } else {
      ctxt_str
    };
    base64::decode_config(&ctxt_str, base64::STANDARD)
  };
  if cyphertext.is_err() {
    return Ok(cx.undefined().upcast());
  }
  let cyphertext = cyphertext.unwrap();

  let private_key = {
    let private_str = cx
      .argument::<JsValue>(1)
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
          cx.throw_error("expected 1st argument to be the keys object or the private key string")
        }
      })?
      .value();
    let vec = utils::decode_key(private_str)
      .or_else(|_| cx.throw_error("cannot base64 decode the private key given to `signObj`"))?;
    ed25519::SecretKey::from_slice(&vec)
      .ok_or(0)
      .or_else(|_| cx.throw_error("cannot decode private key bytes"))?
  };

  let msg = private_box::decrypt(cyphertext.as_slice(), &private_key).ok_or(0);
  if msg.is_err() {
    return Ok(cx.undefined().upcast());
  }
  let msg = msg.unwrap();
  let msg_str = String::from_utf8(msg);
  if msg_str.is_err() {
    return Ok(cx.undefined().upcast());
  }
  let msg_str = msg_str.unwrap();

  let out = {
    let args: Vec<Handle<JsString>> = vec![cx.string(msg_str)];
    cx.compute_scoped(|cx2| utils::json_parse(cx2, args))
  };
  if out.is_err() {
    return Ok(cx.undefined().upcast());
  }
  let out = out.unwrap();

  Ok(out.upcast())
}
