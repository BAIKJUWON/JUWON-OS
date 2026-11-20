/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",          // Docker 이미지를 작게 (node server.js 하나로 실행)
  reactStrictMode: true,
  poweredByHeader: false,
  // NAS에서 처음 빌드할 때 타입 경고 하나로 빌드가 멈추지 않도록. 개발 PC에서는 `npx tsc --noEmit`으로 따로 확인하세요.
  typescript: { ignoreBuildErrors: true },
  eslint: { ignoreDuringBuilds: true },
  // RAM 1GB NAS: 빌드 작업을 여러 개 동시에 띄우지 않아 메모리 최고점을 낮춤
  experimental: { cpus: 1, workerThreads: false },
  // 로컬 개발(npm run dev) 때만 /api 를 백엔드로 넘김. Docker에서는 Caddy가 /api 를 나눠 줍니다.
  async rewrites() {
    const target = process.env.API_DEV_PROXY;
    return target ? [{ source: "/api/:path*", destination: `${target}/api/:path*` }] : [];
  },
  async headers() {
    return [{
      source: "/:path*",
      headers: [
        { key: "X-Frame-Options", value: "SAMEORIGIN" },
        { key: "X-Content-Type-Options", value: "nosniff" },
        { key: "Referrer-Policy", value: "same-origin" },
      ],
    }];
  },
};

export default nextConfig;
