use super::utils::make_keys_obj;
use neon::prelude::*;
use sodiumoxide::crypto::sign::ed25519;
use sodiumoxide::crypto::sign::Seed;

pub fn neon_generate(mut cx: FunctionContext) -> JsResult<JsObject> {
  let args_length = cx.len();
  if args_length == 0 {
    let (pk, sk) = ed25519::gen_keypair();
    return cx.compute_scoped(|mut cx2| make_keys_obj(&mut cx2, &pk, &sk));
  }

  // First argument: curve (default = "ed25519")
  let curve = cx
    .argument::<JsValue>(0)
    .and_then(|v| {
      if v.is_a::<JsString>() {
        v.downcast::<JsString>().or_throw(&mut cx)
      } else {
        Ok(cx.string("ed25519"))
      }
    })
    .or_else(|_| cx.throw_error("failed to understand `curve` argument"))?
    .value();

  // The only valid curve types: ['ed25519']
  if curve != "ed25519" {
    return cx.throw_error("curve argument only supports: ed25519");
  }

  // Second argument: seed
  let maybe_seed = cx
    .argument_opt(1)
    .map(|v| {
      if v.is_a::<JsBuffer>() {
        v.downcast::<JsBuffer>().or_throw(&mut cx)
      } else {
        cx.throw_error("seed argument must be a buffer")
      }
    })
    .transpose()
    .or_else(|_| cx.throw_error("failed to understand `seed` argument"))?;

  // Use seed if given, else, generate from random
  let (pk, sk) = match maybe_seed {
    Some(seed_buffer) => cx.borrow(&seed_buffer, |data| {
      let seed_bytes = data.as_slice::<u8>();
      let seed = Seed::from_slice(seed_bytes).unwrap();
      ed25519::keypair_from_seed(&seed)
    }),
    None => ed25519::gen_keypair(),
  };

  cx.compute_scoped(|mut cx2| make_keys_obj(&mut cx2, &pk, &sk))
}
