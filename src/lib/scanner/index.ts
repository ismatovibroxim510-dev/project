import { checkCookies } from "./checks/cookies";
import { checkDns } from "./checks/dns";
import { checkEmail } from "./checks/email";
import { checkFiles, fetchRobots, fetchSecurityTxt } from "./checks/files";
import { checkHeaders } from "./checks/headers";
import { checkHttps } from "./checks/https";
import { checkLeakage } from "./checks/leakage";
import { detectTechnologies } from "./checks/tech";
import { checkTls } from "./checks/tls";
import { fetchChain, inspectTls, probeTlsVersions, type ChainResult, type Hop } from "./net";
import { exposurePenalties } from "@/lib/intel/shodan";
import type { ShodanIntel } from "@/lib/intel/types";
import { computeGrade } from "./scoring";
import {
  CATEGORY_ORDER,
  type CategoryId,
  type CategoryResult,
  type ReportDetails,
  type ScanReport,
  type Status,
} from "./types";

export { normalizeDomain, DomainError } from "./domain";
export { resolvePublic, resolvePublicAll, BlockedAddressError } from "./net";

export class ScanError extends Error {}

type Progress = (id: CategoryId, status: Status) => void;

/** Pick the response whose headers represent the site: the HTTPS homepage if it loaded, else whatever HTTP returned. */
function pickAnalysed(httpsChain: ChainResult, httpChain: ChainResult): { chain: ChainResult; hop: Hop } | null {
  const httpsFinal = httpsChain.hops.at(-1);
  if (httpsFinal?.url.startsWith("https:")) return { chain: httpsChain, hop: httpsFinal };
  const httpFinal = httpChain.hops.at(-1);
  if (httpFinal) return { chain: httpChain, hop: httpFinal };
  if (httpsFinal) return { chain: httpsChain, hop: httpsFinal };
  return null;
}

/**
 * Run every check against `host` (already validated and resolved to a public IP).
 * Network work runs in parallel; `onProgress` fires as each category completes.
 */
export async function runScan(
  host: string,
  ip: string,
  onProgress: Progress = () => {},
  /** Optional public-exposure data (Shodan) used for score penalties; null/unavailable means no penalty. */
  exposure: Promise<ShodanIntel | null> = Promise.resolve(null),
): Promise<ScanReport> {
  const started = Date.now();
  const done = (c: CategoryResult) => {
    onProgress(c.id, c.status);
    return c;
  };

  // Certificate inspection plus one pinned handshake per TLS version, all through the SSRF-safe lookup.
  const tlsPromise = Promise.all([
    inspectTls(host).then(
      (info) => ({ info }),
      (error: NodeJS.ErrnoException) => ({ error }),
    ),
    probeTlsVersions(host),
  ]).then(([result, protocols]) => {
    const r = checkTls(host, result, protocols);
    done(r.category);
    return r;
  });
  const emailPromise = checkEmail(host).then((r) => {
    done(r.category);
    return r;
  });
  const dnsPromise = checkDns(host).then((r) => {
    done(r.category);
    return r;
  });

  // security.txt and robots.txt are fetched alongside the homepage so the total scan time stays bounded.
  const securityTxtPromise = fetchSecurityTxt(host);
  const robotsHttpsPromise = fetchRobots(host, "https");

  const [httpsChain, httpChain] = await Promise.all([fetchChain(`https://${host}/`), fetchChain(`http://${host}/`)]);
  const analysed = pickAnalysed(httpsChain, httpChain);
  if (!analysed) {
    // Let the other checks settle so no promise is left dangling.
    await Promise.allSettled([tlsPromise, emailPromise, dnsPromise, securityTxtPromise, robotsHttpsPromise]);
    const reason = httpsChain.error ?? httpChain.error ?? httpsChain.stoppedReason ?? "no response";
    throw new ScanError(`Couldn't connect to ${host} over HTTPS or HTTP (${reason}).`);
  }

  const httpsWorks = analysed.hop.url.startsWith("https:");
  const filesPromise = Promise.all([
    securityTxtPromise,
    // HTTP-only sites: robots.txt over HTTPS can't work, so fetch it over HTTP instead.
    httpsWorks ? robotsHttpsPromise : robotsHttpsPromise.then(() => fetchRobots(host, "http")),
  ]).then(([sec, robots]) => {
    const r = checkFiles(sec, robots);
    done(r.category);
    return r;
  });
  const technologies = detectTechnologies(analysed.chain.hops);
  const headers = done(checkHeaders(analysed.hop));
  const results: CategoryResult[] = [
    done(checkHttps(httpsChain, httpChain)),
    headers,
    done(checkCookies(analysed.chain.hops)),
    done(checkLeakage(analysed.hop, technologies)),
  ];
  const [tls, email, dnsResult, files] = await Promise.all([tlsPromise, emailPromise, dnsPromise, filesPromise]);
  results.push(tls.category, email.category, dnsResult.category, files.category);
  const categories = CATEGORY_ORDER.map((id) => results.find((r) => r.id === id)!);

  // Clickjacking demo: only for HTTPS pages with no framing protection and a trusted certificate
  // (an http:// page couldn't be embedded in our https page anyway).
  const framing = headers.findings.find((f) => f.id === "x-frame-options");
  const frameable = !!framing && framing.status !== "pass";
  const details: ReportDetails = {
    tls: tls.details,
    technologies,
    robots: files.robots,
    email: { domain: email.domain, spfRecord: email.spfRecord },
    frame: {
      frameable,
      url: frameable && httpsWorks && !analysed.hop.tlsError ? analysed.hop.url : null,
    },
  };

  const notes: string[] = [];
  const finalUrl = analysed.hop.url;
  if (new URL(finalUrl).hostname !== host) {
    notes.push(`${host} redirects to ${new URL(finalUrl).host}; headers and cookies were checked on the final page.`);
  }
  if (analysed.hop.status >= 400) {
    notes.push(
      `The site answered with HTTP ${analysed.hop.status}. Some sites send different headers to automated tools or on error pages, so results may differ from what browsers see.`,
    );
  }
  if (analysed.chain.stoppedReason) notes.push(`Redirect not followed: ${analysed.chain.stoppedReason}.`);

  const penalties = exposurePenalties(await exposure.catch(() => null));
  const { score, grade, cap } = computeGrade(categories, penalties);
  const findings = categories.flatMap((c) => c.findings);
  return {
    domain: host,
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    finalUrl,
    finalStatus: analysed.hop.status,
    ip,
    score,
    grade,
    cap,
    counts: {
      pass: findings.filter((f) => f.status === "pass").length,
      warn: findings.filter((f) => f.status === "warn").length,
      fail: findings.filter((f) => f.status === "fail").length,
    },
    categories,
    penalties,
    details,
    notes,
  };
}
