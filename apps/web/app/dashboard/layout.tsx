import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Security Dashboard // Live Multi-Repo PR Forensics",
  description:
    "Real-time pull request threat monitoring, repository vulnerability audits, policy toggles, and automated AI security scans across GitHub repositories.",
  alternates: {
    canonical: "https://codefort-web.vercel.app/dashboard",
  },
  openGraph: {
    title: "Security Dashboard // Live Multi-Repo PR Forensics | CodeFort",
    description:
      "Real-time pull request threat monitoring, repository vulnerability audits, and policy management.",
    url: "https://codefort-web.vercel.app/dashboard",
  },
};

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
