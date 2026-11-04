import { helperStartFailure } from "../telemetry/codes";
import { isHelperStartFailure } from "./coreGuards";
import type { RustCore } from "./rustCore";

const HELPER = "telemetryCodes.helperStartFailure";

/** Stage and code of a failed tunnel start from the helper's message, through the Rust core. */
export function helperStartFailureWithCore(core: RustCore, message: string): ReturnType<typeof helperStartFailure> {
  if (core.mode === "ts" || !core.has(HELPER)) return helperStartFailure(message);
  return core.run(HELPER, message, () => helperStartFailure(message), isHelperStartFailure);
}
