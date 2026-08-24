// Types for scripts/dotenv.mjs, which vite.config.ts imports. The loader itself
// is plain JavaScript so that Node can run it from the launcher with no build
// step; this file is what lets `tsc --noEmit` see through it.

/** Where a .env was found, and what it contributed. */
export interface DotenvResult {
  /** Absolute path of the file that was read, or null if none existed. */
  path: string | null;
  /** Keys taken from the file (those not already set in the environment). */
  applied: string[];
  /** Keys present in the file but skipped because the environment had them. */
  skipped: string[];
}

/** Parses .env text into key/value pairs. */
export function parseEnv(text: string): Record<string, string>;

/**
 * Loads the first .env found into process.env without overwriting anything the
 * environment already provides.
 */
export function loadDotenv(explicitPath?: string): DotenvResult;
