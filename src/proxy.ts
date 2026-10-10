import { NextResponse, type NextRequest } from "next/server";

/**
 * Sets a strict, nonce-based Content-Security-Policy on every page.
 * Next.js reads the nonce from the request's CSP header and adds it to its own
 * scripts, so no 'unsafe-inline' is needed for script-src.
 */
export function proxy(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const isDev = process.env.NODE_ENV === "development";

  const csp = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ""}`,
    "style-src 'self' 'unsafe-inline'",
    // Map tiles for the server-location map (Leaflet itself is bundled, so no script host is needed).
    "img-src 'self' data: blob: https://tile.openstreetmap.org",
    "font-src 'self'",
    `connect-src 'self'${isDev ? " ws: wss:" : ""}`,
    // Only our own /frame-demo page may be framed; it in turn allows exactly one scanned origin.
    "frame-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    ...(isDev ? [] : ["upgrade-insecure-requests"]),
  ].join("; ");

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  return response;
}

export const config = {
  matcher: [
    {
      // Pages only: skip API routes, static assets and metadata files.
      source:
        "/((?!api|frame-demo|_next/static|_next/image|favicon.ico|icon.svg|opengraph-image|robots.txt|sitemap.xml).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
