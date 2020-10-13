use super::utils::ContextExt;
use neon::prelude::*;

pub fn neon_get_tag(mut cx: FunctionContext) -> JsResult<JsString> {
  let mut input = cx
    .arg_as::<JsString>(0, "expected string as the 1st argument to `getTag`")?
    .value();
  let output = input.split_off(input.find('.').unwrap_or(input.len()) + 1);

  Ok(cx.string(output))
}
