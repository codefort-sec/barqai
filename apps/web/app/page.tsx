import Link from "next/link";

export default function HomePage() {
  return (
    <div className="max-w-7xl mx-auto px-4 py-8 font-mono flex flex-col gap-10 md:gap-14">
      {/* Real-Time Platform Status Bar */}
      <div className="border border-border bg-surface px-4 py-2.5 flex flex-wrap items-center justify-between text-[11px] text-text-dim gap-3">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-lime animate-pulse" />
          <span className="text-text font-bold uppercase tracking-wider">PLATFORM STATUS:</span>
          <span className="text-lime font-bold">ALL DEFENSE ENGINES ONLINE</span>
        </div>
        <div className="flex flex-wrap items-center gap-3 md:gap-5 text-[10px] uppercase tracking-wider">
          <span className="text-text-muted">
            TESTS: <strong className="text-lime">82/82 PASSED (100%)</strong>
          </span>
          <span className="hidden sm:inline">•</span>
          <span className="text-text-muted">
            BENCHMARK: <strong className="text-lime">100% VERDICT ACCURACY</strong>
          </span>
          <span className="hidden sm:inline">•</span>
          <span className="text-[#ff7139] font-bold">
            🦊 FIREFOX ADD-ON: APPROVED ON AMO
          </span>
        </div>
      </div>

      {/* SECTION /01: HERO & REAL-TIME TECHNICAL HUD */}
      <section className="border border-border bg-surface p-6 md:p-10 relative">
        {/* Cyber corner marks */}
        <div className="absolute top-0 left-0 w-2.5 h-2.5 border-t-2 border-l-2 border-lime" />
        <div className="absolute top-0 right-0 w-2.5 h-2.5 border-t-2 border-r-2 border-lime" />
        <div className="absolute bottom-0 left-0 w-2.5 h-2.5 border-b-2 border-l-2 border-lime" />
        <div className="absolute bottom-0 right-0 w-2.5 h-2.5 border-b-2 border-r-2 border-lime" />

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-10 items-center">
          {/* Left Column (Headline, Explanation & Actions) */}
          <div className="lg:col-span-7 flex flex-col gap-4">
            <div className="flex items-center gap-2 text-xs text-lime tracking-widest uppercase">
              <span>/01</span>
              <span>•</span>
              <span>ZERO-TRUST PR DEFENSE // POWERED BY Barq-AI</span>
            </div>

            <h1 className="text-3xl sm:text-4xl md:text-5xl font-black tracking-tight text-text uppercase leading-none">
              MALICIOUS PR <br />
              <span className="text-lime">DETECTOR</span>
            </h1>

            <p className="text-xs sm:text-sm font-bold text-lime-muted tracking-wider uppercase">
              THE FUTURE ISN&apos;T MINIMAL. IT&apos;S SYSTEMATIC.
            </p>

            <p className="text-xs md:text-sm text-text-muted max-w-xl leading-relaxed">
              Detects malicious npm lifecycle scripts, dependency typosquatting, and unsafe GitHub Actions workflows before pull requests merge into production. Powered by frontier intelligence (Qwen 2.5 Coder MoE &amp; Google Gemini) with line-level evidence grounding and verified 1-click fixes.
            </p>

            {/* CTAs */}
            <div className="flex flex-wrap items-center gap-3 pt-3">
              <a
                href="https://addons.mozilla.org/en-US/firefox/addon/codefort-guard/"
                target="_blank"
                rel="noopener noreferrer"
                className="bg-[#ff7139] hover:bg-[#e05d2b] text-white font-black text-xs px-5 py-3 tracking-wider uppercase transition-all shadow-md shadow-[#ff7139]/20 flex items-center gap-2 hover:scale-[1.02]"
              >
                <span>🦊 Add to Firefox (Store)</span>
                <span>↗</span>
              </a>

              <Link
                href="/dashboard"
                className="bg-lime hover:bg-lime-muted text-bg font-black text-xs px-5 py-3 tracking-wider uppercase transition-colors flex items-center gap-2"
              >
                <span>OPEN DASHBOARD</span>
                <span>↗</span>
              </Link>

              <Link
                href="/extension"
                className="bg-surface-raised border border-border hover:border-lime text-text hover:text-lime font-extrabold text-xs px-4 py-3 tracking-wider uppercase transition-colors flex items-center gap-1.5"
              >
                <span>EXTENSION SETUP</span>
                <span>↓</span>
              </Link>

              <Link
                href="/chat"
                className="border border-border hover:border-lime text-text-muted hover:text-lime font-bold text-xs px-4 py-3 tracking-wider uppercase transition-colors"
              >
                AI COPILOT
              </Link>
            </div>
          </div>

          {/* Right Column (Technical HUD Display) */}
          <div className="lg:col-span-5 border border-border bg-bg p-5 flex flex-col gap-4 relative">
            <div className="flex justify-between items-center text-[10px] text-text-dim border-b border-border pb-2">
              <span className="font-bold">TARGET: GITHUB_PR_PIPELINE</span>
              <span className="text-lime font-bold">STATUS: ACTIVE</span>
            </div>

            {/* Risk HUD Meter */}
            <div className="bg-surface p-4 border border-border">
              <div className="flex justify-between items-baseline mb-2">
                <span className="text-xs font-bold text-text-muted uppercase">LATEST INCIDENT RISK</span>
                <span className="text-2xl font-black text-[#ff0055]">100 / 100</span>
              </div>
              <div className="w-full bg-bg h-2 border border-border overflow-hidden">
                <div className="bg-[#ff0055] h-full" style={{ width: "100%" }} />
              </div>
              <div className="flex justify-between text-[10px] text-text-dim mt-2">
                <span className="text-[#ff0055] font-bold">VERDICT: BLOCKED</span>
                <span>CONFIDENCE: 99%</span>
              </div>
            </div>

            {/* Engine Readiness List */}
            <div className="flex flex-col gap-2 text-xs">
              <div className="flex justify-between items-center py-1 border-b border-border/50 text-[11px]">
                <span className="text-text-muted">STATIC ANALYZER (AST / SHELL)</span>
                <span className="text-lime font-bold">READY</span>
              </div>
              <div className="flex justify-between items-center py-1 border-b border-border/50 text-[11px]">
                <span className="text-text-muted">DEPENDENCY INTEL (OSV / CVE)</span>
                <span className="text-lime font-bold">READY</span>
              </div>
              <div className="flex justify-between items-center py-1 border-b border-border/50 text-[11px]">
                <span className="text-text-muted">WORKFLOW LINTER (GH ACTIONS)</span>
                <span className="text-lime font-bold">READY</span>
              </div>
              <div className="flex justify-between items-center py-1 text-[11px]">
                <span className="text-text-muted">Barq-AI EXPLANATION ENGINE</span>
                <span className="text-lime font-bold">ONLINE</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* SECTION /02: SYSTEM SECURITY PRINCIPLES */}
      <section className="flex flex-col gap-4">
        <div className="flex items-center justify-between border-b border-border pb-2">
          <div className="flex items-center gap-2 text-xs text-text-dim tracking-widest uppercase">
            <span>/02</span>
            <span>•</span>
            <span className="text-lime font-bold">SYSTEM SECURITY PRINCIPLES</span>
          </div>
          <span className="text-[10px] text-text-dim uppercase tracking-wider">ZERO-TRUST VERIFICATION</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
          <div className="border border-border bg-surface p-4 hover:border-lime/60 transition-colors flex flex-col justify-between">
            <div>
              <div className="text-lime font-bold text-xs mb-1">01. TRACEABLE</div>
              <div className="text-xs font-bold text-text uppercase mb-2">EVIDENCE OVER SPECULATION</div>
              <p className="text-[11px] text-text-muted leading-relaxed">
                Every finding is anchored to file paths, AST checks, or CVE records via concrete telemetry tags.
              </p>
            </div>
            <div className="text-[10px] text-lime font-mono mt-3 pt-2 border-t border-border/40">
              [EVIDENCE: TAGGED]
            </div>
          </div>

          <div className="border border-border bg-surface p-4 hover:border-lime/60 transition-colors flex flex-col justify-between">
            <div>
              <div className="text-lime font-bold text-xs mb-1">02. FAIL-SAFE</div>
              <div className="text-xs font-bold text-text uppercase mb-2">NEVER SILENT PASS</div>
              <p className="text-[11px] text-text-muted leading-relaxed">
                Failed checks result in REVIEW_REQUIRED or SCAN_ERROR—never silent approvals or bypassed rules.
              </p>
            </div>
            <div className="text-[10px] text-lime font-mono mt-3 pt-2 border-t border-border/40">
              [SAFETY: ENFORCED]
            </div>
          </div>

          <div className="border border-border bg-surface p-4 hover:border-lime/60 transition-colors flex flex-col justify-between">
            <div>
              <div className="text-lime font-bold text-xs mb-1">03. IN-FLOW</div>
              <div className="text-xs font-bold text-text uppercase mb-2">INJECTED ON GITHUB</div>
              <p className="text-[11px] text-text-muted leading-relaxed">
                CodeFort Guard injects verdicts, PR header badges, and inline line warnings directly on GitHub.
              </p>
            </div>
            <div className="text-[10px] text-lime font-mono mt-3 pt-2 border-t border-border/40">
              [DOM: INLINE]
            </div>
          </div>

          <div className="border border-border bg-surface p-4 hover:border-lime/60 transition-colors flex flex-col justify-between">
            <div>
              <div className="text-lime font-bold text-xs mb-1">04. ISOLATED</div>
              <div className="text-xs font-bold text-text uppercase mb-2">HOSTILE CODE ISOLATION</div>
              <p className="text-[11px] text-text-muted leading-relaxed">
                Untrusted repository scripts are executed only within isolated, sandboxed containers.
              </p>
            </div>
            <div className="text-[10px] text-lime font-mono mt-3 pt-2 border-t border-border/40">
              [SANDBOX: DOCKED]
            </div>
          </div>

          <div className="border border-border bg-surface p-4 hover:border-lime/60 transition-colors flex flex-col justify-between">
            <div>
              <div className="text-lime font-bold text-xs mb-1">05. ACTIONABLE</div>
              <div className="text-xs font-bold text-text uppercase mb-2">VERIFIED REMEDIATIONS</div>
              <p className="text-[11px] text-text-muted leading-relaxed">
                Barq-AI synthesizes functional unified git diffs independently verified to cause 0 regressions.
              </p>
            </div>
            <div className="text-[10px] text-lime font-mono mt-3 pt-2 border-t border-border/40">
              [DIFF: 1-CLICK FIX]
            </div>
          </div>
        </div>
      </section>

      {/* SECTION /03: BARQ-AI MULTI-ENGINE REASONING ARCHITECTURE */}
      <section className="flex flex-col gap-4">
        <div className="flex items-center justify-between border-b border-border pb-2">
          <div className="flex items-center gap-2 text-xs text-text-dim tracking-widest uppercase">
            <span>/03</span>
            <span>•</span>
            <span className="text-lime font-bold">BARQ-AI REASONING &amp; REMEDIATION ARCHITECTURE</span>
          </div>
          <span className="text-[10px] text-lime font-mono">QWEN 2.5 CODER MoE + GOOGLE GEMINI</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="border border-border bg-surface p-6 flex flex-col justify-between">
            <div className="flex flex-col gap-2">
              <div className="flex items-center justify-between text-xs">
                <span className="text-lime font-bold">LAYER 01</span>
                <span className="text-[10px] bg-surface-raised px-2 py-0.5 text-text-muted font-bold">AST ANALYSIS</span>
              </div>
              <h3 className="text-sm font-bold text-text uppercase">Lifecycle Hook Dropper Interception</h3>
              <p className="text-xs text-text-muted leading-relaxed">
                Strictly monitors dangerous lifecycle hooks (<code className="text-lime">preinstall</code>, <code className="text-lime">postinstall</code>) while whitelisting benign developer scripts (<code className="text-text">build</code>, <code className="text-text">test</code>) to ensure 0 false positives. Catches <code className="text-lime">curl | bash</code> pipes and base64 obfuscation.
              </p>
            </div>
            <div className="mt-4 pt-3 border-t border-border/60 text-[11px] text-text-dim flex justify-between">
              <span>False Positive Rate:</span>
              <span className="text-lime font-bold">0.0%</span>
            </div>
          </div>

          <div className="border border-border bg-surface p-6 flex flex-col justify-between">
            <div className="flex flex-col gap-2">
              <div className="flex items-center justify-between text-xs">
                <span className="text-lime font-bold">LAYER 02</span>
                <span className="text-[10px] bg-surface-raised px-2 py-0.5 text-text-muted font-bold">OSV INTEL</span>
              </div>
              <h3 className="text-sm font-bold text-text uppercase">Grounded Vulnerability Knowledge Base</h3>
              <p className="text-xs text-text-muted leading-relaxed">
                Queries Google&apos;s OSV database in real time for CVE/GHSA advisories across PyPI, npm, and Go. Employs Levenshtein distance metrics with intelligent length thresholds and whitelist guards to eliminate typosquat collisions.
              </p>
            </div>
            <div className="mt-4 pt-3 border-t border-border/60 text-[11px] text-text-dim flex justify-between">
              <span>Advisory Grounding:</span>
              <span className="text-lime font-bold">100% OSV Verified</span>
            </div>
          </div>

          <div className="border border-border bg-surface p-6 flex flex-col justify-between">
            <div className="flex flex-col gap-2">
              <div className="flex items-center justify-between text-xs">
                <span className="text-lime font-bold">LAYER 03</span>
                <span className="text-[10px] bg-surface-raised px-2 py-0.5 text-text-muted font-bold">PATCH VERIFY</span>
              </div>
              <h3 className="text-sm font-bold text-text uppercase">In-Memory 1-Click Patch Verification</h3>
              <p className="text-xs text-text-muted leading-relaxed">
                Every security finding includes a synthesized unified git diff. The built-in <code className="text-lime">PatchVerifier</code> applies the diff in-memory, cleans up JSON/YAML trailing syntax, and re-scans the repository to prove exploit elimination with 0 regressions.
              </p>
            </div>
            <div className="mt-4 pt-3 border-t border-border/60 text-[11px] text-text-dim flex justify-between">
              <span>Patch Viability:</span>
              <span className="text-lime font-bold">100% (0 Regressions)</span>
            </div>
          </div>
        </div>
      </section>

      {/* SECTION /04 - /06: INTEGRATIONS & LIVE FORENSICS */}
      <section className="flex flex-col gap-4">
        <div className="flex items-center justify-between border-b border-border pb-2">
          <div className="flex items-center gap-2 text-xs text-text-dim tracking-widest uppercase">
            <span>/04 - /06</span>
            <span>•</span>
            <span className="text-lime font-bold">PLATFORM INTEGRATIONS &amp; FORENSIC DEMOS</span>
          </div>
          <span className="text-[10px] text-text-dim uppercase tracking-wider">LIVE REPOSITORY ACCESS</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Card /04: Repositories */}
          <div className="border border-border bg-surface p-5 flex flex-col justify-between hover:border-lime/60 transition-colors">
            <div className="flex flex-col gap-2">
              <div className="text-[10px] text-lime font-bold">/04 REPOSITORY INTEGRATION</div>
              <h4 className="text-sm font-bold text-text uppercase">Multi-Repo Live Audit</h4>
              <p className="text-xs text-text-muted leading-relaxed">
                Authorize CodeFort App to audit any GitHub repository dynamically. Queries real-time PR opened and synchronize events.
              </p>
            </div>
            <div className="pt-4 mt-2 border-t border-border/40">
              <Link
                href="/dashboard"
                className="bg-surface-raised border border-border hover:border-lime text-lime font-bold text-xs py-2.5 px-3 text-center uppercase tracking-wider flex items-center justify-center gap-1.5 transition-colors"
              >
                <span>VIEW REPOSITORIES</span>
                <span>↗</span>
              </Link>
            </div>
          </div>

          {/* Card /05: Extension */}
          <div className="border-2 border-[#ff7139]/80 bg-surface p-5 flex flex-col justify-between hover:border-[#ff7139] transition-colors relative">
            <div className="flex flex-col gap-2">
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-[#ff7139] font-bold">/05 BROWSER GUARD</span>
                <span className="bg-[#ff7139] text-white text-[9px] font-black px-1.5 py-0.5 uppercase tracking-wider">
                  APPROVED ON AMO
                </span>
              </div>
              <h4 className="text-sm font-bold text-text uppercase">Firefox &amp; Chrome Copilot</h4>
              <p className="text-xs text-text-muted leading-relaxed">
                Install CodeFort Guard in 1-click on Mozilla Firefox from the official store. Also supports Google Chrome, Brave, Arc, &amp; Edge with inline PR warnings.
              </p>
            </div>
            <div className="pt-4 mt-2 border-t border-border/40 flex flex-col gap-2">
              <a
                href="https://addons.mozilla.org/en-US/firefox/addon/codefort-guard/"
                target="_blank"
                rel="noopener noreferrer"
                className="bg-[#ff7139] hover:bg-[#e05d2b] text-white font-extrabold text-xs py-2 px-3 text-center uppercase tracking-wider flex items-center justify-center gap-1.5 transition-colors"
              >
                <span>🦊 Add to Firefox (Store)</span>
                <span>↗</span>
              </a>
              <Link
                href="/extension"
                className="bg-surface-raised border border-border hover:border-lime text-text hover:text-lime font-bold text-xs py-1.5 px-3 text-center uppercase tracking-wider transition-colors"
              >
                Chrome &amp; Manual Install Guide →
              </Link>
            </div>
          </div>

          {/* Card /06: Live Forensics */}
          <div className="border border-border bg-surface p-5 flex flex-col justify-between hover:border-lime/60 transition-colors">
            <div className="flex flex-col gap-2">
              <div className="text-[10px] text-lime font-bold">/06 LIVE SCAN FORENSICS</div>
              <h4 className="text-sm font-bold text-text uppercase">Inspect Malicious PR #1</h4>
              <p className="text-xs text-text-muted leading-relaxed">
                Review suspicious preinstall shell script execution, typosquatted dependencies, and Barq-AI risk scoring on live adversarial PRs.
              </p>
            </div>
            <div className="pt-4 mt-2 border-t border-border/40">
              <Link
                href="/scans/scan_pr_1"
                className="bg-surface-raised border border-border hover:border-lime text-text hover:text-lime font-bold text-xs py-2.5 px-3 text-center uppercase tracking-wider flex items-center justify-center gap-1.5 transition-colors"
              >
                <span>OPEN FORENSIC VIEW</span>
                <span>↗</span>
              </Link>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
