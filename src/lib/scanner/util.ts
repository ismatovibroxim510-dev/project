import { CATEGORY_META, type CategoryId, type CategoryResult, type Finding, type Status } from "./types";

/** Make a raw value safe to show: strip control characters and cap the length. */
export function cleanEvidence(value: string | undefined | null, max = 600): string | undefined {
  if (value == null) return undefined;
  const cleaned = value.replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, "").trim();
  if (!cleaned) return undefined;
  return cleaned.length > max ? `${cleaned.slice(0, max)}…` : cleaned;
}

export function finding(f: Finding): Finding {
  return { ...f, evidence: cleanEvidence(f.evidence) };
}

const RANK: Record<Status, number> = { info: 0, pass: 1, warn: 2, fail: 3 };

export function worstStatus(findings: Finding[]): Status {
  let worst: Status = "pass";
  for (const f of findings) if (RANK[f.status] > RANK[worst]) worst = f.status;
  return worst;
}

export function category(id: CategoryId, findings: Finding[]): CategoryResult {
  const meta = CATEGORY_META[id];
  const score = findings.reduce((sum, f) => sum + f.points, 0);
  const maxScore = findings.reduce((sum, f) => sum + f.maxPoints, 0);
  if (maxScore !== meta.maxScore) {
    throw new Error(`Category ${id} max points ${maxScore} != ${meta.maxScore}`);
  }
  return {
    id,
    title: meta.title,
    description: meta.description,
    score: Math.round(score * 10) / 10,
    maxScore,
    status: worstStatus(findings),
    findings,
  };
}

export function header(headers: Record<string, string[]> | undefined, name: string): string | undefined {
  const values = headers?.[name.toLowerCase()];
  if (!values || values.length === 0) return undefined;
  return values.join(", ");
}
