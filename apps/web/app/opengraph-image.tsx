import { ImageResponse } from "next/og";

export const runtime = "edge";
export const alt = "CodeFort // Zero-Trust PR & Supply Chain Defense";
export const size = {
  width: 1200,
  height: 630,
};
export const contentType = "image/png";

export default async function Image() {
  return new ImageResponse(
    (
      <div
        style={{
          background: "#070807",
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          padding: "60px",
          fontFamily: "monospace",
          border: "8px solid #d7ff35",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "12px",
              color: "#d7ff35",
              fontSize: "24px",
              fontWeight: 900,
            }}
          >
            <span>[CODEFORT_SYS // 2026]</span>
          </div>
          <div
            style={{
              background: "#ff7139",
              color: "#ffffff",
              fontSize: "18px",
              fontWeight: 800,
              padding: "8px 16px",
              borderRadius: "4px",
            }}
          >
            OFFICIAL MOZILLA ADD-ON APPROVED
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          <div
            style={{
              fontSize: "64px",
              fontWeight: 900,
              color: "#ffffff",
              textTransform: "uppercase",
              lineHeight: 1.1,
            }}
          >
            ZERO-TRUST PR &amp; <br />
            <span style={{ color: "#d7ff35" }}>SUPPLY CHAIN DEFENSE</span>
          </div>
          <div
            style={{
              fontSize: "22px",
              color: "#a2a59a",
              maxWidth: "900px",
              lineHeight: 1.4,
            }}
          >
            Powered by Barq-AI with frontier intelligence (Qwen 2.5 Coder MoE + Google Gemini),
            OSV evidence grounding, deterministic risk scoring, and autonomous 1-click patch verification.
          </div>
        </div>

        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            borderTop: "2px solid #222622",
            paddingTop: "24px",
            color: "#686d64",
            fontSize: "18px",
          }}
        >
          <span style={{ color: "#00ff66" }}>✓ 82/82 TESTS PASSED (100%)</span>
          <span style={{ color: "#d7ff35" }}>✓ 100% VERDICT ACCURACY</span>
          <span>https://codefort-web.vercel.app</span>
        </div>
      </div>
    ),
    {
      ...size,
    }
  );
}
