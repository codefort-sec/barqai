import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Install CodeFort Guard // Official Firefox Add-on & Chrome Extension",
  description:
    "Install the CodeFort Guard browser extension on Mozilla Firefox (official AMO store) and Google Chrome. Real-time GitHub PR vulnerability inspection, inline risk badges, and Barq-AI 1-click diff fixes.",
  alternates: {
    canonical: "https://codefort-web.vercel.app/extension",
  },
  openGraph: {
    title: "Install CodeFort Guard // Firefox Add-ons & Chrome Extension",
    description:
      "Install the CodeFort Guard browser extension in 1-click on Mozilla Firefox (AMO) and Google Chrome.",
    url: "https://codefort-web.vercel.app/extension",
  },
};

export default function ExtensionLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
