import { ImageResponse } from "next/og";
import { site } from "@/lib/site";

export const alt = `${site.name}: free website security scanner`;
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function OpengraphImage() {
  const grades = [
    { g: "A+", c: "#34d399" },
    { g: "B", c: "#a3e635" },
    { g: "C", c: "#fbbf24" },
    { g: "F", c: "#fb7185" },
  ];
  return new ImageResponse(
    <div
      style={{
        width: "100%",
        height: "100%",
        display: "flex",
        flexDirection: "column",
        justifyContent: "space-between",
        padding: 72,
        background: "radial-gradient(ellipse at 30% 0%, #1e1b4b 0%, #05080f 60%)",
        color: "white",
        fontFamily: "sans-serif",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 18 }}>
        <div
          style={{
            width: 64,
            height: 64,
            borderRadius: 16,
            background: "linear-gradient(135deg, #6366f1, #22d3ee)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <svg
            width="36"
            height="36"
            viewBox="0 0 24 24"
            fill="none"
            stroke="white"
            strokeWidth="3"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="m5 12.5 4.5 4.5L19 7.5" />
          </svg>
        </div>
        <div style={{ fontSize: 40, fontWeight: 700 }}>{site.name}</div>
      </div>
      <div style={{ display: "flex", flexDirection: "column" }}>
        <div style={{ fontSize: 76, fontWeight: 700, lineHeight: 1.05, letterSpacing: -2 }}>
          How secure is your website?
        </div>
        <div style={{ marginTop: 24, fontSize: 30, color: "#94a3b8" }}>
          HTTPS · TLS · Security headers · SPF/DMARC · Cookies
        </div>
      </div>
      <div style={{ display: "flex", gap: 18 }}>
        {grades.map(({ g, c }) => (
          <div
            key={g}
            style={{
              width: 96,
              height: 96,
              borderRadius: 48,
              border: `6px solid ${c}`,
              color: c,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: 38,
              fontWeight: 700,
            }}
          >
            {g}
          </div>
        ))}
      </div>
    </div>,
    size,
  );
}
