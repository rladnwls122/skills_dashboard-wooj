import { readFile } from "node:fs/promises";
import * as ts from "typescript";

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

// Node does not execute TypeScript source by default. Transpile the small,
// dependency-free server modules used by the test scripts while preserving ESM
// imports for the resolver above.
export async function load(url, context, next) {
  if (url.endsWith(".ts")) {
    const source = await readFile(new URL(url), "utf8");
    const output = ts.transpileModule(source, {
      compilerOptions: {
        target: ts.ScriptTarget.ES2022,
        module: ts.ModuleKind.ESNext,
        jsx: ts.JsxEmit.ReactJSX,
      },
      fileName: new URL(url).pathname,
    });
    return { format: "module", source: output.outputText, shortCircuit: true };
  }
  return next(url, context);
}
