import { frameDemoNotice, frameDemoResponse, parseFrameTarget } from "@/lib/frame-demo";

/**
 * Inner page of the clickjacking demo, embedded by the scan report. It is
 * generated per request so its CSP can allow frame-src for exactly one origin.
 */
export function GET(request: Request) {
  const target = parseFrameTarget(new URL(request.url).searchParams.get("url"));
  if (!target) return frameDemoNotice("Invalid demo URL.", 400);

  // Browsers send Sec-Fetch-Dest. Only render the embedded site when this page is itself inside
  // our report's iframe, so the route can't be used as a standalone page that frames other sites.
  const dest = request.headers.get("sec-fetch-dest");
  if (dest && dest !== "iframe") {
    return frameDemoNotice("This page is only used inside a scan report's clickjacking demo.", 400);
  }
  return frameDemoResponse(target);
}
