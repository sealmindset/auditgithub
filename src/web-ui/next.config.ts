import type { NextConfig } from "next";

const API_BACKEND = process.env.API_BASE || "http://api:8000";

const nextConfig: NextConfig = {
  output: "standalone",
  async rewrites() {
    return [
      {
        source: "/api/proxy/:path*",
        destination: `${API_BACKEND}/:path*`,
      },
    ];
  },
};

export default nextConfig;
