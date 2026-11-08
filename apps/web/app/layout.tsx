import "./globals.css";
import type { Metadata } from "next";
import { Navbar } from "@/components/Navbar";

export const metadata: Metadata = {
  metadataBase: new URL("https://codefort-web.vercel.app"),
  title: {
    default: "CodeFort // Zero-Trust PR & Supply Chain Defense Powered by Barq-AI",
    template: "%s | CodeFort",
  },
  description:
    "Next-generation AI security platform that intercepts malicious pull requests, detects software supply chain poisoning, and prevents CI/CD workflow injection attacks before code merges into production. Available as an approved Firefox Add-on, Chrome extension, and automated GitHub PR security auditor.",
  keywords: [
    "CodeFort",
    "CodeFort Guard",
    "Barq-AI",
    "malicious PR detection",
    "supply chain security",
    "software supply chain security",
    "GitHub pull request security",
    "GitHub Actions security",
    "npm preinstall attack",
    "typosquatting detection",
    "open source vulnerability scanner",
    "OSV database",
    "Qwen 2.5 Coder security",
    "Google Gemini security",
    "Firefox security extension",
    "Chrome GitHub extension",
    "zero trust code review",
    "autonomous patch remediation",
  ],
  authors: [{ name: "CodeFort Security Team", url: "https://github.com/codefort-sec" }],
  creator: "CodeFort Security",
  publisher: "CodeFort",
  applicationName: "CodeFort Guard",
  generator: "Next.js",
  alternates: {
    canonical: "https://codefort-web.vercel.app",
  },
  openGraph: {
    type: "website",
    locale: "en_US",
    url: "https://codefort-web.vercel.app",
    siteName: "CodeFort Security",
    title: "CodeFort // Zero-Trust PR & Supply Chain Defense Powered by Barq-AI",
    description:
      "Intercept malicious pull requests, detect software supply chain poisoning, and prevent CI/CD workflow injection attacks before merging. Approved Mozilla Firefox Add-on & Manifest V3 Chrome Extension.",
    images: [
      {
        url: "/og-image.png",
        width: 1200,
        height: 630,
        alt: "CodeFort // Zero-Trust PR & Supply Chain Defense",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "CodeFort // Zero-Trust PR & Supply Chain Defense",
    description:
      "Intercept malicious PRs and software supply chain attacks before merge with Barq-AI reasoning and official Firefox Add-on.",
    images: ["/og-image.png"],
    creator: "@codefort_sec",
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      "max-video-preview": -1,
      "max-image-preview": "large",
      "max-snippet": -1,
    },
  },
  icons: {
    icon: "/favicon.ico",
  },
  verification: {
    google: "q8BWZlYhmKeyf02yNufmghk7j6KQCe-crJJ--BKIL7I",
  },
};

const jsonLd = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "SoftwareApplication",
      "name": "CodeFort Guard",
      "operatingSystem": "All",
      "applicationCategory": "SecurityApplication",
      "description":
        "Zero-trust browser extension and GitHub pull request security copilot powered by Barq-AI.",
      "url": "https://codefort-web.vercel.app",
      "downloadUrl": "https://addons.mozilla.org/en-US/firefox/addon/codefort-guard/",
      "offers": {
        "@type": "Offer",
        "price": "0",
        "priceCurrency": "USD",
      },
      "author": {
        "@type": "Organization",
        "name": "CodeFort Security",
        "url": "https://github.com/codefort-sec",
      },
      "sameAs": [
        "https://github.com/codefort-sec/codefort",
        "https://addons.mozilla.org/en-US/firefox/addon/codefort-guard/",
      ],
    },
    {
      "@type": "Organization",
      "name": "CodeFort Security",
      "url": "https://codefort-web.vercel.app",
      "sameAs": ["https://github.com/codefort-sec"],
    },
  ],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <head>
        <meta
          name="google-site-verification"
          content="q8BWZlYhmKeyf02yNufmghk7j6KQCe-crJJ--BKIL7I"
        />
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
      </head>
      <body className="min-h-screen flex flex-col bg-bg text-text tech-grid-bg">
        <Navbar />
        <main className="flex-1 flex flex-col">{children}</main>

        {/* Footer with Hazard Stripe from design.md */}
        <footer className="border-t border-border bg-surface mt-auto">
          <div className="hazard-stripe" />
          <div className="max-w-7xl mx-auto px-4 py-8 flex flex-col md:flex-row items-center justify-between text-xs text-text-dim font-mono gap-4">
            <div className="flex items-center gap-3">
              <span className="text-lime font-bold">CODEFORT_SYS // 2026</span>
              <span>•</span>
              <span>Barq-AI EXPLANATION ENGINE ENABLED</span>
            </div>
            <div className="flex items-center gap-4">
              <a
                href="https://addons.mozilla.org/en-US/firefox/addon/codefort-guard/"
                target="_blank"
                rel="noopener noreferrer"
                className="text-[#ff7139] hover:underline flex items-center gap-1 font-bold"
              >
                <span>🦊 FIREFOX ADD-ON (AMO)</span>
                <span>↗</span>
              </a>
              <span>•</span>
              <a
                href="https://github.com/codefort-sec/codefort"
                target="_blank"
                rel="noopener noreferrer"
                className="hover:text-text transition-colors"
              >
                GITHUB REPO ↗
              </a>
              <span>•</span>
              <span className="text-lime">&gt; ACCESS GRANTED_</span>
            </div>
          </div>
        </footer>
      </body>
    </html>
  );
}
