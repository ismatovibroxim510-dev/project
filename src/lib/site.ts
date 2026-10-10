/** Central place for branding and SEO text. Rename the project here. */
function resolveSiteUrl(): string {
  if (process.env.NEXT_PUBLIC_SITE_URL) return process.env.NEXT_PUBLIC_SITE_URL.replace(/\/$/, "");
  // Vercel sets this automatically to the production domain (custom domain if configured).
  if (process.env.VERCEL_PROJECT_PRODUCTION_URL) return `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`;
  return "http://localhost:3000";
}

export const site = {
  name: "SiteGrade",
  title: "SiteGrade — Free Website Security Scanner",
  tagline: "Check any website's security in seconds",
  description:
    "Free website security scanner. Check HTTPS, TLS certificates, security headers, email spoofing protection (SPF/DMARC) and cookie flags, get an A+ to F grade and plain-English fixes.",
  url: resolveSiteUrl(),
  author: "Ibrohim Ismatov",
  keywords: [
    "website security scanner",
    "security headers check",
    "SSL certificate checker",
    "HSTS",
    "Content Security Policy",
    "SPF DMARC checker",
    "cookie security",
    "website security grade",
  ],
} as const;
