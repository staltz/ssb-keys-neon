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
  cx.argument::<JsValue>(0)
    .and_then(|v| {
      if v.is_a::<JsString>() {
        v.downcast::<JsString>().or_throw(&mut cx)
      } else {
        Ok(cx.string("ed25519"))
      }
    })
    .map(|v| v.value())
    // Assert that curve is one of the valid types: ['ed25519']
    .and_then(|curve| {
      if curve == "ed25519" {
        Ok(())
      } else {
        cx.throw_error("curve argument only supports: ed25519")
      }
    })
    // Second argument: seed
    .and_then(|_| {
      cx.argument_opt(1)
        .map(|v| {
          if v.is_a::<JsBuffer>() {
            v.downcast::<JsBuffer>().or_throw(&mut cx)
          } else {
            cx.throw_error("seed argument must be a buffer")
          }
        })
        .transpose()
    })
    // Use seed if given, else, generate from random
    .map(|maybe_seed| match maybe_seed {
      Some(seed_buffer) => cx.borrow(&seed_buffer, |data| {
        let seed_bytes = data.as_slice::<u8>();
        let seed = Seed::from_slice(seed_bytes).unwrap();
        ed25519::keypair_from_seed(&seed)
      }),
      None => ed25519::gen_keypair(),
    })
    .and_then(|(pk, sk)| cx.compute_scoped(|mut cx2| make_keys_obj(&mut cx2, &pk, &sk)))
}
