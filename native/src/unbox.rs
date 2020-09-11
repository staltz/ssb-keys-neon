use super::utils;
use neon::prelude::*;
use neon::result::Throw;
use sodiumoxide::crypto::sign::ed25519;
use sodiumoxide::crypto::sign::PublicKey;

pub fn neon_box(mut cx: FunctionContext) -> JsResult<JsString> {
  let msg_buf = {
    let arg1 = cx.argument::<JsValue>(0)?;
    let stringified = cx
      .compute_scoped(|cx2| utils::json_stringify(cx2, vec![arg1]))
      .or_else(|_| cx.throw_error("failed to JSON.stringify the given `msg` argument"))?
      .value();
    let buf = cx.compute_scoped(|mut cx2| utils::string_to_buffer(&mut cx2, stringified))?;
    buf
  };

  let msg = cx.borrow(&msg_buf, |data| data.as_slice::<u8>());

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

  let multiboxed = private_box::encrypt(msg, recps.as_slice());
  let mut out = base64::encode_config(multiboxed.as_slice(), base64::STANDARD);
  out.push_str(".box");

  Ok(cx.string(out))
}
