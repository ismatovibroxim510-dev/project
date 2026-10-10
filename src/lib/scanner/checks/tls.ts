import { friendlyNetError, type TlsInfo } from "../net";
import { LEGACY_TLS_PREFIX } from "../scoring";
import type { CategoryResult, Finding, TlsDetails } from "../types";
import { category, finding } from "../util";

const DAY = 24 * 60 * 60 * 1000;
const SAN_DISPLAY_LIMIT = 25;

const CERT_ERRORS: Record<string, string> = {
  CERT_HAS_EXPIRED: "The certificate has expired.",
  CERT_NOT_YET_VALID: "The certificate is not valid yet (its start date is in the future).",
  DEPTH_ZERO_SELF_SIGNED_CERT: "The certificate is self-signed, so browsers don't trust it.",
  SELF_SIGNED_CERT_IN_CHAIN: "The certificate chain contains an untrusted self-signed certificate.",
  UNABLE_TO_VERIFY_LEAF_SIGNATURE:
    "The certificate chain is incomplete (the server isn't sending its intermediate certificate).",
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
    "The certificate was issued by an untrusted authority, or the intermediate certificate is missing.",
  ERR_TLS_CERT_ALTNAME_INVALID: "The certificate was issued for a different domain name.",
  CERT_REVOKED: "The certificate has been revoked.",
  CERT_SIGNATURE_FAILURE: "The certificate signature is invalid.",
};

const CERT_FIXES: Record<string, string> = {
  CERT_HAS_EXPIRED:
    "Renew the certificate now. Use automatic renewal (Let's Encrypt with Certbot/Caddy, or your host's managed certificates) so this can't happen again.",
  UNABLE_TO_VERIFY_LEAF_SIGNATURE:
    'Configure the server to send the full chain: use the "fullchain.pem" file (not "cert.pem") in your web server config.',
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
    "Install the full certificate chain, and make sure the certificate comes from a publicly trusted authority.",
  ERR_TLS_CERT_ALTNAME_INVALID:
    "Issue a certificate that covers this exact hostname (and www., if used). Let's Encrypt can include several names in one certificate.",
  DEPTH_ZERO_SELF_SIGNED_CERT:
    "Replace the self-signed certificate with one from a trusted authority such as Let's Encrypt (free).",
};

/** RSA/DSA below 2048 bits or elliptic curves below 224 bits are considered breakable. */
export function isWeakKey(key: { type: string; bits: number | null } | null): boolean {
  if (!key || key.bits == null) return false;
  if (key.type === "RSA" || key.type === "RSA-PSS" || key.type === "DSA") return key.bits < 2048;
  if (key.type === "EC") return key.bits < 224;
  return false;
}

export function isWeakSignature(alg: string | null | undefined): boolean {
  return !!alg && /md5|md2|sha1(?!\d)|sha-1(?!\d)/i.test(alg);
}

function protocolsFinding(protocols: TlsDetails["protocols"]): Finding {
  const result = (v: string) => protocols.find((p) => p.version === v)?.result ?? "unknown";
  const evidence = protocols
    .map(
      (p) =>
        `${p.version}: ${p.result === "supported" ? "accepted" : p.result === "rejected" ? "not accepted" : "could not determine"}`,
    )
    .join("\n");
  const base = {
    id: "tls-protocols",
    title: "TLS protocol versions",
    maxPoints: 5,
    explanation:
      "TLS 1.0 and 1.1 are from 1999 and 2006 and have known weaknesses (BEAST, weak hashes, no modern ciphers). All major browsers dropped them in 2020, so the only clients still using them are outdated or malicious. Servers should accept only TLS 1.2 and 1.3.",
    evidence,
  };
  const fix =
    "Disable TLS 1.0 and 1.1 and keep TLS 1.2 and 1.3 enabled. Nginx: `ssl_protocols TLSv1.2 TLSv1.3;`. Apache: `SSLProtocol -all +TLSv1.2 +TLSv1.3`. Cloudflare: SSL/TLS → Edge Certificates → Minimum TLS Version → TLS 1.2.";

  if (result("TLS 1.0") === "supported") {
    return finding({
      ...base,
      status: "fail",
      points: 0,
      summary: `${LEGACY_TLS_PREFIX}0${result("TLS 1.1") === "supported" ? " and TLS 1.1" : ""}.`,
      fix,
    });
  }
  if (result("TLS 1.1") === "supported") {
    return finding({ ...base, status: "warn", points: 2, summary: `${LEGACY_TLS_PREFIX}1.`, fix });
  }
  const has12 = result("TLS 1.2") === "supported";
  const has13 = result("TLS 1.3") === "supported";
  if (!has12 && !has13) {
    return finding({
      ...base,
      status: "warn",
      points: 2,
      summary: "Could not confirm support for TLS 1.2 or 1.3.",
      fix: "Make sure TLS 1.2 and 1.3 are enabled.",
    });
  }
  const unknownLegacy = result("TLS 1.0") === "unknown" || result("TLS 1.1") === "unknown";
  const legacyText = unknownLegacy ? "Old versions could not be fully tested" : "TLS 1.0 and 1.1 are refused";
  if (has13) {
    return finding({
      ...base,
      status: "pass",
      points: 5,
      summary: `${legacyText}; TLS ${has12 ? "1.2 and 1.3 are" : "1.3 is"} supported.`,
    });
  }
  return finding({
    ...base,
    status: "pass",
    points: 4,
    summary: `${legacyText}; TLS 1.2 is supported but TLS 1.3 isn't.`,
    fix: "Enable TLS 1.3 for better security and faster connections (nginx: `ssl_protocols TLSv1.2 TLSv1.3;`).",
  });
}

function baseDomain(name: string): string {
  return name.replace(/^\*\./, "").split(".").slice(-2).join(".");
}

export function buildTlsDetails(info: TlsInfo | null, protocols: TlsDetails["protocols"]): TlsDetails {
  return {
    protocols,
    negotiated: info?.protocol ?? null,
    cipher: info?.cipher ?? null,
    keyExchange: info?.keyExchange ?? null,
    key: info?.key ?? null,
    signatureAlgorithm: info?.signatureAlgorithm ?? null,
    issuerOrg: info?.issuer ?? null,
    chain: info?.chain ?? [],
    sans: (info?.altNames ?? []).slice(0, SAN_DISPLAY_LIMIT),
    sanTotal: info?.altNames.length ?? 0,
  };
}

export function checkTls(
  host: string,
  result: { info: TlsInfo } | { error: NodeJS.ErrnoException },
  protocols: TlsDetails["protocols"],
): { category: CategoryResult; details: TlsDetails } {
  if ("error" in result) {
    const reason = friendlyNetError(result.error);
    const evidence = `Connection to port 443 failed: ${reason}`;
    const noCert = {
      status: "fail" as const,
      points: 0,
      summary: "No certificate to check.",
    };
    return {
      details: buildTlsDetails(null, protocols),
      category: category("tls", [
        finding({
          id: "tls-valid",
          title: "Certificate is valid and trusted",
          status: "fail",
          points: 0,
          maxPoints: 10,
          summary: "Could not establish a modern (TLS 1.2+) connection on port 443.",
          explanation:
            "A valid certificate proves visitors are talking to the real site. Without one, browsers show a full-page security warning.",
          fix: "Enable HTTPS with a certificate from a trusted authority (Let's Encrypt is free and automatic).",
          evidence,
        }),
        finding({
          id: "tls-expiry",
          title: "Certificate expiry",
          maxPoints: 4,
          ...noCert,
          explanation: "Expired certificates cause browsers to block the site.",
          fix: "Set up a certificate with automatic renewal.",
        }),
        protocolsFinding(protocols),
        finding({
          id: "tls-key",
          title: "Key strength",
          maxPoints: 2,
          ...noCert,
          explanation: "The certificate's key must be long enough that it can't be cracked.",
        }),
        finding({
          id: "tls-signature",
          title: "Signature algorithm",
          maxPoints: 1,
          ...noCert,
          explanation: "The certificate's signature must use a modern hash such as SHA-256.",
        }),
      ]),
    };
  }

  const info = result.info;
  const findings: Finding[] = [];
  const issuer = info.issuer ?? "unknown issuer";
  const certSummary = [
    info.subject ? `Subject: ${info.subject}` : null,
    `Issuer: ${issuer}`,
    info.validFrom ? `Valid from: ${info.validFrom}` : null,
    info.validTo ? `Valid until: ${info.validTo}` : null,
  ]
    .filter(Boolean)
    .join("\n");

  if (info.authorized) {
    findings.push(
      finding({
        id: "tls-valid",
        title: "Certificate is valid and trusted",
        status: "pass",
        points: 10,
        maxPoints: 10,
        summary: `Trusted certificate issued by ${issuer}.`,
        explanation:
          "A valid certificate from a trusted authority proves visitors are talking to the real site and not an impostor.",
        evidence: certSummary,
      }),
    );
  } else {
    const code = info.authorizationError ?? "UNKNOWN";
    findings.push(
      finding({
        id: "tls-valid",
        title: "Certificate is valid and trusted",
        status: "fail",
        points: 0,
        maxPoints: 10,
        summary: CERT_ERRORS[code] ?? `The certificate is not trusted (${code}).`,
        explanation:
          'Browsers show a full-page "Your connection is not private" warning for untrusted certificates. Most visitors leave, and those who click through are exposed to impersonation attacks.',
        fix:
          CERT_FIXES[code] ??
          "Install a valid certificate from a trusted authority (Let's Encrypt is free) that covers this hostname, and serve the full certificate chain.",
        evidence: `Error: ${code}\n${certSummary}`,
      }),
    );
  }

  const validTo = info.validTo ? new Date(info.validTo) : null;
  const expiryExplanation =
    "When a certificate expires, browsers block the site with a security warning until it's renewed.";
  if (!validTo || Number.isNaN(validTo.getTime())) {
    findings.push(
      finding({
        id: "tls-expiry",
        title: "Certificate expiry",
        status: "warn",
        points: 2,
        maxPoints: 4,
        summary: "Could not read the certificate's expiry date.",
        explanation: expiryExplanation,
      }),
    );
  } else {
    const days = Math.floor((validTo.getTime() - Date.now()) / DAY);
    const date = validTo.toISOString().slice(0, 10);
    if (days < 0) {
      findings.push(
        finding({
          id: "tls-expiry",
          title: "Certificate expiry",
          status: "fail",
          points: 0,
          maxPoints: 4,
          summary: `Expired ${-days} day${days === -1 ? "" : "s"} ago (${date}).`,
          explanation: expiryExplanation,
          fix: "Renew the certificate immediately and enable automatic renewal.",
        }),
      );
    } else if (days < 30) {
      findings.push(
        finding({
          id: "tls-expiry",
          title: "Certificate expiry",
          status: "warn",
          points: 2,
          maxPoints: 4,
          summary: `Expires in ${days} day${days === 1 ? "" : "s"} (${date}).`,
          explanation: expiryExplanation,
          fix: "Renew soon. If you use Let's Encrypt, check that automatic renewal (e.g. `certbot renew` cron/timer) is actually running - it normally renews 30 days before expiry.",
        }),
      );
    } else {
      findings.push(
        finding({
          id: "tls-expiry",
          title: "Certificate expiry",
          status: "pass",
          points: 4,
          maxPoints: 4,
          summary: `Valid for another ${days} days (until ${date}).`,
          explanation: expiryExplanation,
        }),
      );
    }
  }

  findings.push(protocolsFinding(protocols));

  const key = info.key;
  const keyText = key ? `${key.type}${key.bits ? ` ${key.bits}-bit` : ""}` : "unknown";
  const keyExplanation =
    "The certificate's public key protects the connection's identity. RSA keys need at least 2048 bits and elliptic-curve keys at least 224 bits (256 is standard); shorter keys can be broken with enough computing power.";
  findings.push(
    isWeakKey(key)
      ? finding({
          id: "tls-key",
          title: "Key strength",
          status: "fail",
          points: 0,
          maxPoints: 2,
          summary: `Weak ${keyText} key.`,
          explanation: keyExplanation,
          fix: "Generate a new key (RSA 2048/3072-bit or ECDSA P-256) and get a new certificate for it. Certbot: `certbot certonly --key-type ecdsa`.",
          evidence: keyText,
        })
      : finding({
          id: "tls-key",
          title: "Key strength",
          status: "pass",
          points: 2,
          maxPoints: 2,
          summary: `${keyText} key${key?.type === "EC" ? " (elliptic curve, equivalent to RSA 3072+)" : ""}.`,
          explanation: keyExplanation,
        }),
  );

  const weakInChain = info.chain.filter((c) => c.role !== "root" && isWeakSignature(c.signatureAlgorithm));
  const sigExplanation =
    "Certificates are signed by the authority that issued them. Signatures using SHA-1 or MD5 can be forged, so browsers reject them; SHA-256 or stronger is required.";
  findings.push(
    weakInChain.length
      ? finding({
          id: "tls-signature",
          title: "Signature algorithm",
          status: "fail",
          points: 0,
          maxPoints: 1,
          summary: `Weak signature (${weakInChain[0].signatureAlgorithm}) on ${weakInChain[0].subject}.`,
          explanation: sigExplanation,
          fix: "Reissue the certificate; every public CA now signs with SHA-256 or stronger. Make sure the server sends the current intermediate certificate.",
        })
      : finding({
          id: "tls-signature",
          title: "Signature algorithm",
          status: "pass",
          points: 1,
          maxPoints: 1,
          summary: `Signed with ${info.signatureAlgorithm ?? "a modern algorithm"}.`,
          explanation: sigExplanation,
        }),
  );

  const details = buildTlsDetails(info, protocols);
  const otherDomains = [...new Set(info.altNames.map(baseDomain))].filter((d) => d !== baseDomain(host));
  findings.push(
    finding({
      id: "tls-details",
      title: "Connection & certificate details",
      status: "info",
      points: 0,
      maxPoints: 0,
      summary: [
        info.cipher ? `Cipher ${info.cipher}` : null,
        `${info.altNames.length} name${info.altNames.length === 1 ? "" : "s"} on the certificate`,
        otherDomains.length
          ? `including ${otherDomains.length} other domain${otherDomains.length === 1 ? "" : "s"} (${otherDomains.slice(0, 3).join(", ")}${otherDomains.length > 3 ? ", …" : ""})`
          : null,
      ]
        .filter(Boolean)
        .join(", ")
        .concat("."),
      explanation:
        "The certificate lists every domain it's valid for (Subject Alternative Names). Shared certificates, common on CDNs, can reveal other sites run by the same owner or hosted on the same service. This is informational and doesn't affect the score.",
      evidence: [
        info.protocol ? `Protocol: ${info.protocol}` : null,
        info.cipher ? `Cipher: ${info.cipher}` : null,
        info.keyExchange ? `Key exchange: ${info.keyExchange}` : null,
        ...info.chain.map((c) => `${c.role}: ${c.subject} (issued by ${c.issuer}; ${c.key}; ${c.signatureAlgorithm})`),
      ]
        .filter(Boolean)
        .join("\n"),
    }),
  );

  return { category: category("tls", findings), details };
}
