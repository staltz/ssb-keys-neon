use super::utils;
// TODO: check if sodiumoxide has these
use libsodium_sys::crypto_box_PUBLICKEYBYTES as PK_BYTES;
use libsodium_sys::crypto_box_SECRETKEYBYTES as SK_BYTES;
use libsodium_sys::crypto_scalarmult_BYTES as SCALARMULT_BYTES;
use libsodium_sys::crypto_secretbox_KEYBYTES as SB_KEYBYTES;
use libsodium_sys::crypto_secretbox_NONCEBYTES as SB_NONCEBYTES;
use neon::prelude::*;
use neon::result::Throw;
use sodiumoxide::crypto::sign::ed25519;
use sodiumoxide::randombytes::randombytes;
use std::convert::TryInto;
use std::mem::size_of;

pub struct EphPublicKey(pub [u8; 32]);

impl EphPublicKey {
  /// The size of an EphPublicKey, in bytes (32).
  pub const SIZE: usize = size_of::<Self>();
}

fn pk_to_curve(k: &ed25519::PublicKey) -> Option<EphPublicKey> {
  let mut buf = [0; EphPublicKey::SIZE];

  let ok = unsafe {
    libsodium_sys::crypto_sign_ed25519_pk_to_curve25519(buf.as_mut_ptr(), k.0.as_ptr()) == 0
  };

  if ok {
    Some(EphPublicKey(buf))
  } else {
    None
  }
}

fn keypair() -> Option<([u8; PK_BYTES as usize], [u8; SK_BYTES as usize])> {
  let mut pk = [0; PK_BYTES as usize];
  let mut sk = [0; SK_BYTES as usize];

  let ok = unsafe { libsodium_sys::crypto_box_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) == 0 };

  if ok {
    Some((pk, sk))
  } else {
    None
  }
}

fn scalarmult(sk: [u8; 32], pk: [u8; 32]) -> Option<[u8; SCALARMULT_BYTES as usize]> {
  let mut secret = [0; SCALARMULT_BYTES as usize];
  let ok =
    unsafe { libsodium_sys::crypto_scalarmult(secret.as_mut_ptr(), sk.as_ptr(), pk.as_ptr()) == 0 };
  if ok {
    Some(secret)
  } else {
    None
  }
}

fn secretbox(
  ptxt: Vec<u8>,
  nonce: [u8; SB_NONCEBYTES as usize],
  key: [u8; SB_KEYBYTES as usize],
) -> Option<Vec<u8>> {
  let mac_size = libsodium_sys::crypto_secretbox_MACBYTES as usize;
  let mut ctxt = vec![0; ptxt.len() + mac_size];
  let ok = unsafe {
    let c = ctxt.as_mut_ptr();
    let m = ptxt.as_ptr();
    let mlen = ptxt.len() as u64;
    let n = nonce.as_ptr();
    let k = key.as_ptr();
    libsodium_sys::crypto_secretbox_easy(c, m, mlen, n, k) == 0
  };
  if ok {
    Some(ctxt)
  } else {
    None
  }
}

fn multibox(msg: &[u8], recipients: Vec<EphPublicKey>) -> Vec<u8> {
  let nonce = {
    let boxed_slice = randombytes(SB_NONCEBYTES as usize).into_boxed_slice();
    let boxed_array: Box<[u8; SB_NONCEBYTES as usize]> = match boxed_slice.try_into() {
      Ok(ba) => ba,
      Err(_) => panic!("randombytes did not return the correct length"),
    };
    *boxed_array
  };
  let key = {
    let boxed_slice = randombytes(SB_KEYBYTES as usize).into_boxed_slice();
    let boxed_array: Box<[u8; SB_KEYBYTES as usize]> = match boxed_slice.try_into() {
      Ok(ba) => ba,
      Err(_) => panic!("randombytes did not give us specified length"),
    };
    *boxed_array
  };
  let (onetime_pk, onetime_sk) = keypair().unwrap();
  let mut length_and_key: Vec<u8> = vec![];
  length_and_key.push(recipients.len() as u8);
  length_and_key.extend(&key);
  let mut result: Vec<u8> = vec![];
  result.extend(&nonce);
  result.extend(&onetime_pk);
  let recipients_secretbox = recipients
    .iter()
    .filter_map(|recipient_pk| {
      let EphPublicKey(r_pk) = recipient_pk;
      secretbox(
        length_and_key.clone(),
        nonce,
        scalarmult(onetime_sk, *r_pk).unwrap(),
      )
    })
    .fold(vec![] as Vec<u8>, |mut acc, x| {
      acc.extend(&x);
      acc
    });
  result.extend(recipients_secretbox);
  result.extend(secretbox(msg.to_vec(), nonce, key).unwrap());
  result
}

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

  let recps: Vec<EphPublicKey> = cx
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
    .filter_map(|public_key| pk_to_curve(&public_key))
    .collect();

  let multiboxed = multibox(msg, recps);
  let mut out = base64::encode_config(multiboxed.as_slice(), base64::STANDARD);
  out.push_str(".box");

  Ok(cx.string(out))
}
