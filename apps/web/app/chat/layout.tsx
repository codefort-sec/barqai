import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Barq-AI Copilot Studio // Unified Git Diff Code Rewriter",
  description:
    "Interactive AI security assistant powered by frontier intelligence (Qwen 2.5 Coder MoE & Google Gemini). Deep code vulnerability diagnostics, root-cause explanation, and 1-click verified patch rewriting.",
  alternates: {
    canonical: "https://codefort-web.vercel.app/chat",
  },
  openGraph: {
    title: "Barq-AI Copilot Studio // AI Security Assistant | CodeFort",
    description:
      "Interactive AI cybersecurity copilot powered by Qwen 2.5 Coder and Google Gemini with verified unified git diff rewriting.",
    url: "https://codefort-web.vercel.app/chat",
  },
};

export default function ChatLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
