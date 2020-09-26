use neon::prelude::*;

pub fn neon_get_tag(mut cx: FunctionContext) -> JsResult<JsString> {
  let mut input = cx
    .argument::<JsString>(0)
    .and_then(|v| {
      if v.is_a::<JsString>() {
        v.downcast::<JsString>().or_throw(&mut cx)
      } else {
        cx.throw_error("expected string as the 1st argument to `getTag`")
      }
    })
    .or_else(|_| cx.throw_error("failed to understand the `path` argument"))?
    .value();

  let output = input.split_off(input.find('.').unwrap_or(input.len()) + 1);

  Ok(cx.string(output))
}
