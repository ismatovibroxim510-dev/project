/** Client-safe RDAP helpers (no network code). */
import type { RdapIntel } from "./types";

const DAY = 86400e3;

export function domainAgeDays(registered: string | null, now = new Date()): number | null {
  if (!registered) return null;
  return Math.floor((now.getTime() - Date.parse(registered)) / DAY);
}

export function humanAge(days: number): string {
  if (days < 1) return "less than a day old";
  if (days < 60) return `${days} day${days === 1 ? "" : "s"} old`;
  const months = Math.floor(days / 30.44);
  if (months < 24) return `${months} months old`;
  const years = Math.floor(days / 365.25);
  return `${years} years old`;
}

export interface RdapWarning {
  id: "new-domain" | "expiring";
  text: string;
}

export function rdapWarnings(r: RdapIntel, now = new Date()): RdapWarning[] {
  const out: RdapWarning[] = [];
  const age = domainAgeDays(r.registered, now);
  if (age !== null && age < 30) {
    out.push({
      id: "new-domain",
      text: "Very new domains are often used for phishing. Be careful if this site asks for passwords or payment.",
    });
  }
  if (r.expires) {
    const left = Math.floor((Date.parse(r.expires) - now.getTime()) / DAY);
    if (left < 30) {
      out.push({
        id: "expiring",
        text:
          left < 0
            ? "The domain registration has expired. If it isn't renewed, anyone could register it."
            : `The domain registration expires in ${left} day${left === 1 ? "" : "s"}. If it lapses, the site goes offline and someone else could register it.`,
      });
    }
  }
  return out;
}
