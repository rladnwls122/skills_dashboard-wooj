import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  serverExternalPackages: ["better-sqlite3", "@kubernetes/client-node"],
};

export default nextConfig;
