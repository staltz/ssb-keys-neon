use super::utils;
use neon::prelude::*;
use neon::result::Throw;
use private_box;
use sodiumoxide::crypto::box_::PublicKey as EphPublicKey;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::sign::ed25519;
use ssb_crypto::handshake::derive_shared_secret_sk;

pub fn neon_box(mut cx: FunctionContext) -> JsResult<JsString> {
  let msg = {
    let arg1 = cx.argument::<JsValue>(0)?;
    let stringified = cx
      .compute_scoped(|cx2| utils::json_stringify(cx2, vec![arg1]))
      .or_else(|_| cx.throw_error("failed to JSON.stringify the given `msg` argument"))?
      .value();
    stringified.into_bytes()
  };

  let recps: Vec<ed25519::PublicKey> = cx
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

const BOXED_KEY_SIZE_BYTES: usize = 32 + 1 + 16;

// FIXME: move this to private-box-rs so that it's public and `decrypt` is
// split into unboxKey + unboxBody
fn multibox_open_key(cyphertext: &[u8], secret_key: &ed25519::SecretKey) -> Option<Vec<u8>> {
  let nonce = secretbox::Nonce::from_slice(&cyphertext[0..24])?;
  let eph_pk = EphPublicKey::from_slice(&cyphertext[24..56])?;
  let secret = derive_shared_secret_sk(secret_key, &eph_pk)?;
  let kkey = secretbox::Key::from_slice(&secret[..])?;
  let key_with_prefix = cyphertext[56..]
    .chunks_exact(BOXED_KEY_SIZE_BYTES)
    .find_map(|buf| secretbox::open(&buf, &nonce, &kkey).ok());
  key_with_prefix
}

// FIXME: move this to private-box-rs so that it's public
fn multibox_open_body(cyphertext: &[u8], key_with_prefix: &[u8]) -> Option<Vec<u8>> {
  let nonce = secretbox::Nonce::from_slice(&cyphertext[0..24])?;

  let num_recps = key_with_prefix[0] as usize;
  let key = secretbox::Key::from_slice(&key_with_prefix[1..])?;

  let boxed_msg = &cyphertext[(56 + BOXED_KEY_SIZE_BYTES * num_recps)..];
  secretbox::open(&boxed_msg, &nonce, &key).ok()
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

  let opened_key = multibox_open_key(&cyphertext, &private_key);

  if opened_key.is_none() {
    return Ok(cx.undefined().upcast());
  }

  let buffer = cx
    .compute_scoped(|mut cx2| utils::bytes_to_buffer(&mut cx2, opened_key.unwrap().as_slice()))
    .or_else(|_| cx.throw_error("failed to create JsBuffer for `unboxKey`"))?;

  Ok(buffer.upcast())
}

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

  let msg = multibox_open_body(&cyphertext, &opened_key);

  if msg.is_none() {
    return Ok(cx.undefined().upcast());
  }
  let msg_str = String::from_utf8(msg.unwrap());
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
