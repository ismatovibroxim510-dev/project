import type { CategoryResult, Grade, GradeCap, Penalty } from "./types";

export const GRADE_THRESHOLDS: Array<{ grade: Grade; min: number }> = [
  { grade: "A+", min: 95 },
  { grade: "A", min: 85 },
  { grade: "B", min: 70 },
  { grade: "C", min: 55 },
  { grade: "D", min: 40 },
  { grade: "F", min: 0 },
];

/** Summary prefix the TLS check uses when TLS 1.0 or 1.1 is accepted. */
export const LEGACY_TLS_PREFIX = "Still accepts TLS 1.";

const ORDER: Grade[] = ["A+", "A", "B", "C", "D", "F"];

export function gradeForScore(score: number): Grade {
  return GRADE_THRESHOLDS.find((t) => score >= t.min)?.grade ?? "F";
}

function worse(a: Grade, b: Grade): Grade {
  return ORDER.indexOf(a) >= ORDER.indexOf(b) ? a : b;
}

/**
 * Weighted score out of 100 (the category max scores add up to 100), mapped to
 * a letter grade. Some problems are severe enough to cap the grade no matter how
 * good the rest is - a site with an untrusted certificate shouldn't get an A.
 */
export function computeGrade(
  categories: CategoryResult[],
  penalties: Penalty[] = [],
): { score: number; grade: Grade; cap: GradeCap | null } {
  const raw = categories.reduce((sum, c) => sum + c.score, 0) + penalties.reduce((sum, p) => sum + p.points, 0);
  const score = Math.max(0, Math.round(raw));
  const findings = categories.flatMap((c) => c.findings);
  const failed = (id: string) => findings.some((f) => f.id === id && f.status === "fail");

  let grade = gradeForScore(score);
  // A+ is reserved for sites with no failing checks at all.
  if (grade === "A+" && (findings.some((f) => f.status === "fail") || penalties.length)) grade = "A";

  // The most severe applicable cap wins.
  const caps: GradeCap[] = [];
  if (failed("https-available")) caps.push({ grade: "F", reason: "The site can't be loaded securely over HTTPS." });
  if (failed("tls-valid")) {
    caps.push({
      grade: "D",
      reason: "The TLS certificate isn't trusted, so browsers show a security warning to every visitor.",
    });
  }
  if (failed("tls-expiry")) caps.push({ grade: "D", reason: "The TLS certificate has expired." });
  if (failed("tls-key")) caps.push({ grade: "C", reason: "The certificate uses a weak key that could be broken." });
  if (findings.some((f) => f.id === "tls-protocols" && f.summary.startsWith(LEGACY_TLS_PREFIX))) {
    caps.push({ grade: "B", reason: "The server still accepts outdated TLS 1.0/1.1 connections." });
  }
  for (const p of penalties) if (p.capsGrade) caps.push({ grade: p.capsGrade, reason: `${p.label}. ${p.reason}` });
  let cap: GradeCap | null = caps.reduce<GradeCap | null>(
    (w, c) => (!w || worse(c.grade, w.grade) === c.grade ? c : w),
    null,
  );
  if (cap) {
    const capped = worse(grade, cap.grade);
    if (capped === grade) cap = null; // the cap didn't change anything
    grade = capped;
  }
  return { score, grade, cap };
}
