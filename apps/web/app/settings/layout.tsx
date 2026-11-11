import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Extension Pairing & Repository Security Policies",
  description:
    "Generate secure single-use pairing tokens to authenticate CodeFort Guard browser extension and configure repository blocking thresholds.",
  alternates: {
    canonical: "https://codefort-web.vercel.app/settings",
  },
  openGraph: {
    title: "Extension Pairing & Repository Security Policies | CodeFort",
    description:
      "Generate secure single-use pairing tokens to authenticate CodeFort Guard browser extension.",
    url: "https://codefort-web.vercel.app/settings",
  },
};

export default function SettingsLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
