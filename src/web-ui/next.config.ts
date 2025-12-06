import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${process.env.API_BASE || "http://localhost:8000"}/:path*`,
      },
    ];
  },
};

export default nextConfig;
