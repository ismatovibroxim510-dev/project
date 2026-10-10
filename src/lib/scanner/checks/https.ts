import type { ChainResult } from "../net";
import type { CategoryResult } from "../types";
import { category, finding } from "../util";

function describeChain(chain: ChainResult): string {
  const lines = chain.hops.map((h) => `${h.status} ${h.url}`);
  if (chain.error) lines.push(`error: ${chain.error}`);
  if (chain.stoppedReason) lines.push(`stopped: ${chain.stoppedReason}`);
  return lines.join("\n");
}

export function checkHttps(httpsChain: ChainResult, httpChain: ChainResult): CategoryResult {
  const httpsFinal = httpsChain.hops.at(-1);
  const httpsWorks = !!httpsFinal && httpsFinal.url.startsWith("https:");
  const downgrades = !!httpsFinal && httpsFinal.url.startsWith("http:");

  const available =
    httpsWorks && httpsFinal.tlsError
      ? finding({
          id: "https-available",
          title: "Site loads over HTTPS",
          status: "warn",
          points: 4,
          maxPoints: 8,
          summary: `HTTPS responds (status ${httpsFinal.status}), but the certificate isn't trusted, so browsers block the page with a warning.`,
          explanation:
            "HTTPS encrypts traffic between visitors and the site, but only works if the browser trusts the certificate. See the TLS certificate section for details.",
          fix: "Fix the certificate problem reported in the TLS certificate section.",
          evidence: describeChain(httpsChain),
        })
      : httpsWorks
        ? finding({
            id: "https-available",
            title: "Site loads over HTTPS",
            status: "pass",
            points: 8,
            maxPoints: 8,
            summary: `HTTPS responded with status ${httpsFinal.status}.`,
            explanation:
              "HTTPS encrypts traffic between visitors and the site so nobody on the network (public Wi-Fi, ISPs) can read or tamper with it.",
            evidence: describeChain(httpsChain),
          })
        : finding({
            id: "https-available",
            title: "Site loads over HTTPS",
            status: "fail",
            points: 0,
            maxPoints: 8,
            summary: downgrades
              ? "HTTPS redirects visitors back to insecure HTTP."
              : `The site could not be loaded over HTTPS${httpsChain.error ? ` (${httpsChain.error})` : ""}.`,
            explanation:
              "Without HTTPS, everything visitors send and receive - passwords, forms, cookies - travels in plain text and can be read or modified by anyone on the network.",
            fix: downgrades
              ? "Remove the redirect from HTTPS to HTTP and serve the site over HTTPS only."
              : "Enable HTTPS. Most hosts (Vercel, Netlify, Cloudflare) do this automatically; on your own server use a free Let's Encrypt certificate via Certbot or Caddy.",
            evidence: describeChain(httpsChain),
          });

  const httpFinal = httpChain.hops.at(-1);
  let redirect;
  const base = {
    id: "http-redirect",
    title: "HTTP redirects to HTTPS",
    maxPoints: 4,
    explanation:
      "People often type a bare domain, which browsers try over plain HTTP first. Redirecting to HTTPS makes sure they end up on the encrypted site.",
    evidence: describeChain(httpChain),
  };
  if (!httpFinal) {
    // Port 80 closed or not answering: nothing is served in plain text.
    redirect = finding({
      ...base,
      status: httpsWorks ? "pass" : "fail",
      points: httpsWorks ? 4 : 0,
      summary: `Plain HTTP is not served (${httpChain.error ?? "no response"}), so nothing is exposed unencrypted.`,
      fix: httpsWorks
        ? "Optional: answer on port 80 with a 301 redirect to HTTPS so visitors who type the bare domain don't see a connection error."
        : "Serve the site over HTTPS and redirect HTTP to it.",
    });
  } else if (httpFinal.url.startsWith("https:")) {
    const first = httpChain.hops[0];
    const firstLocation = first?.headers["location"]?.[0] ?? "";
    let firstIsHttps = false;
    try {
      firstIsHttps = new URL(firstLocation, first.url).protocol === "https:";
    } catch {}
    redirect = finding({
      ...base,
      status: "pass",
      points: 4,
      summary: firstIsHttps
        ? `HTTP immediately redirects (${first.status}) to HTTPS.`
        : "HTTP eventually reaches HTTPS, but only after an intermediate plain-HTTP redirect.",
      fix: firstIsHttps
        ? undefined
        : "Redirect straight to the HTTPS version of the same hostname first, then to any other host. This lets HSTS take effect.",
    });
  } else if (httpChain.stoppedReason) {
    redirect = finding({
      ...base,
      status: "warn",
      points: 2,
      summary: `HTTP redirect chain could not be completed: ${httpChain.stoppedReason}.`,
      fix: "Make HTTP redirect directly to https://<your-domain>/ with a 301 status.",
    });
  } else {
    redirect = finding({
      ...base,
      status: "fail",
      points: 0,
      summary: `HTTP serves content (status ${httpFinal.status}) without redirecting to HTTPS.`,
      fix: 'Add a permanent (301) redirect from http:// to https:// for every path. On Nginx: `return 301 https://$host$request_uri;`. On Apache: `Redirect permanent / https://example.com/`. Most hosting dashboards have a "Force HTTPS" toggle.',
    });
  }

  return category("https", [available, redirect]);
}
