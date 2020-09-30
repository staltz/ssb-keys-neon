use super::utils::{make_keys_obj, HandleExt, OptionExt};
use neon::prelude::*;
use ssb_crypto::Keypair;

pub fn neon_generate(mut cx: FunctionContext) -> JsResult<JsObject> {
  let args_length = cx.len();
  if args_length == 0 {
    let keypair = Keypair::generate();
    return make_keys_obj(&mut cx, &keypair);
  }

  // First argument: curve (default = "ed25519")
  let curve = if let Some(s) = cx
    .argument::<JsValue>(0)
    .unwrap()
    .try_downcast::<JsString>()
  {
    s.value()
  } else {
    "ed25519".to_string()
  };

  // The only valid curve types: ['ed25519']
  if curve != "ed25519" {
    return cx.throw_error("curve argument only supports: ed25519");
  }

  // Second argument: seed
  let maybe_seed = cx
    .argument_opt(1)
    .map(|v| {
      v.try_downcast::<JsBuffer>()
        .or_throw(&mut cx, "seed argument must be a buffer")
    })
    .transpose()?;

  // Use seed if given, else, generate from random
  let keypair = match maybe_seed {
    Some(seed_buffer) => {
      let seed_bytes = cx.borrow(&seed_buffer, |data| data.as_slice::<u8>());
      Keypair::from_seed(&seed_bytes).or_throw(&mut cx, "seed buffer must be 32 bytes")
    }
    None => Ok(Keypair::generate()),
  }?;

  make_keys_obj(&mut cx, &keypair)
}
