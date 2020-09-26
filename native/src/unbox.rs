use super::utils::{self, arg_as_string_or_field, OptionExt};
use arrayvec::ArrayVec;
use neon::prelude::*;
use neon::result::Throw;
use ssb_crypto::ephemeral::sk_to_curve;
use ssb_crypto::{Keypair, PublicKey};

pub fn neon_box(mut cx: FunctionContext) -> JsResult<JsString> {
  let arg1 = cx.argument::<JsValue>(0)?;
  let msg = utils::json_stringify(&mut cx, ArrayVec::from([arg1]))?
    .value()
    .into_bytes();

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
      let public_key: Result<PublicKey, Throw> = {
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
        PublicKey::from_base64(&public_str).or_throw(&mut cx, "cannot base64 decode the public key")
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
    base64::decode_config(ctxt_str.trim_end_matches(".box"), base64::STANDARD)
  };
  if cyphertext.is_err() {
    return Ok(cx.undefined().upcast());
  }
  let cyphertext = cyphertext.unwrap();

  let private_key = {
    let private_str = arg_as_string_or_field(&mut cx, 1, "private").or_throw(
      &mut cx,
      "expected 2nd argument to be the keys object or the private key string",
    )?;
    Keypair::from_base64(&private_str).or_throw(
      &mut cx,
      "cannot base64 decode the private key given to `signObj`",
    )?
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
  let msg_str = cx.string(msg_str.unwrap());

  let out = utils::json_parse(&mut cx, msg_str);
  if out.is_err() {
    return Ok(cx.undefined().upcast());
  }
  let out = out.unwrap();

  Ok(out.upcast())
}

pub fn neon_unbox_key(mut cx: FunctionContext) -> JsResult<JsValue> {
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
    base64::decode_config(ctxt_str.trim_end_matches(".box"), base64::STANDARD)
  };
  if cyphertext.is_err() {
    return Ok(cx.undefined().upcast());
  }
  let cyphertext = cyphertext.unwrap();

  let keypair = {
    let private_str = arg_as_string_or_field(&mut cx, 1, "private").or_throw(
      &mut cx,
      "expected 2nd argument to be the keys object or the private key string",
    )?;
    Keypair::from_base64(&private_str).or_throw(
      &mut cx,
      "cannot base64 decode the private key given to `signObj`",
    )?
  };

  let opened_key = private_box::decrypt_key(&cyphertext, &keypair);
  if opened_key.is_none() {
    return Ok(cx.undefined().upcast());
  }

  let buffer = utils::bytes_to_buffer(&mut cx, &opened_key.unwrap().as_array())?;
  Ok(buffer.upcast())
}

// TODO should also allow JsBuffer ciphertext
pub fn neon_unbox_body(mut cx: FunctionContext) -> JsResult<JsValue> {
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

  let opened_key_buf = cx.argument::<JsValue>(1).and_then(|v| {
    if v.is_a::<JsBuffer>() {
      v.downcast::<JsBuffer>().or_throw(&mut cx)
    } else {
      cx.throw_error("expected 2nd argument to be a buffer for the opened key")
    }
  })?;
  let opened_key = cx.borrow(&opened_key_buf, |data| data.as_slice::<u8>());

  let msg = private_box::decrypt_body_with_key_bytes(&cyphertext, &opened_key);

  if msg.is_none() {
    return Ok(cx.undefined().upcast());
  }
  let msg_str = String::from_utf8(msg.unwrap());
  if msg_str.is_err() {
    return Ok(cx.undefined().upcast());
  }
  let msg_str = cx.string(msg_str.unwrap());

  let out = utils::json_parse(&mut cx, msg_str);
  if out.is_err() {
    return Ok(cx.undefined().upcast());
  }
  let out = out.unwrap();

  Ok(out.upcast())
}

// ssbSecretKeyToPrivateBoxSecret
pub fn neon_sk_to_curve(mut cx: FunctionContext) -> JsResult<JsValue> {
  let keypair = {
    let private_str = arg_as_string_or_field(&mut cx, 0, "private").or_throw(
      &mut cx,
      "expected 1st argument to be the keys object or the private key string",
    )?;

    Keypair::from_base64(&private_str).or_throw(
      &mut cx,
      "cannot base64 decode the private key given to `signObj`",
    )?
  };

  let curve = sk_to_curve(&keypair.secret);
  if curve.is_none() {
    return cx.throw_error("failed to run ssbSecretKeyToPrivateBoxSecret");
  }

  let buffer = utils::bytes_to_buffer(&mut cx, &curve.unwrap().0)?;
  Ok(buffer.upcast())
}
