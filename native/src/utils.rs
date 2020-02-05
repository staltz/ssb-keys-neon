extern crate neon;

use neon::prelude::*;
use sodiumoxide::crypto::sign::ed25519::{PublicKey, SecretKey};

// TODO this should probably be public in ssb-keyfile
pub fn encode_key(bytes: &[u8]) -> String {
  let mut out = base64::encode_config(bytes, base64::STANDARD);
  out.push_str(".ed25519");
  out
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
