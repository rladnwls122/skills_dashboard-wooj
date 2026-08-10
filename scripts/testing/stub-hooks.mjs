// Lets plain Node import the app's .ts server modules directly.
// - "server-only" is a Next build-time guard that throws outside a server
//   bundle; stub it to an empty module.
// - TS sources import siblings extensionless ("./config"); Node needs ".ts".
export function resolve(specifier, context, next) {
  if (specifier === "server-only") {
    return { url: "data:text/javascript,export{}", shortCircuit: true };
  }
  if (specifier.startsWith(".") && !/\.[cm]?[jt]s$/.test(specifier)) {
    try {
      return next(`${specifier}.ts`, context);
    } catch {
      // fall through to the unmodified specifier
    }
  }
  return next(specifier, context);
}
