/**
 * CODEFORT Guard - PR Header Badge Injector
 * Injects Cyber Brutalist security status badge into GitHub Pull Request header.
 */

import React from "react";
import ReactDOM from "react-dom/client";
import { ExtensionPRStatusResponse, ExtensionSummaryResponse } from "../shared/types";

export const BADGE_ROOT_ID = "codefort-guard-pr-header-badge";

interface BadgeProps {
  status: ExtensionPRStatusResponse | null;
  summary: ExtensionSummaryResponse | null;
  loading: boolean;
  error?: string | null;
  onOpenSidePanel?: () => void;
}

export const PRSecurityBadge: React.FC<BadgeProps> = ({
  status,
  summary,
  loading,
  error,
  onOpenSidePanel,
}) => {
  const [expanded, setExpanded] = React.useState(false);

  if (loading) {
    return (
      <span className="codefort-badge-container loading">
        <span className="codefort-badge-dot pulse" />
        <span className="codefort-badge-title">CODEFORT: SCANNING...</span>
      </span>
    );
  }

  if (error) {
    return (
      <span className="codefort-badge-container error" title={error}>
        <span className="codefort-badge-dot error" />
        <span className="codefort-badge-title">CODEFORT: OFFLINE</span>
      </span>
    );
  }

  const verdict = status?.verdict || "PASS";
  const riskScore = status?.risk_score ?? (verdict === "BLOCKED" ? 85 : verdict === "REVIEW_REQUIRED" ? 45 : 0);

  let verdictClass = "pass";
  let verdictText = "PASS";
  let explanation = "No blocking security findings were reported.";

  if (verdict === "BLOCKED" || riskScore >= 70) {
    verdictClass = "blocked";
    verdictText = "BLOCK";
    explanation = "A verified blocking security policy was triggered.";
  } else if (verdict === "REVIEW_REQUIRED" || riskScore >= 30) {
    verdictClass = "review";
    verdictText = "REVIEW";
    explanation = "Security findings need developer review.";
  }

  return (
    <span
      className={`codefort-badge-container ${verdictClass}`}
      onClick={() => setExpanded(!expanded)}
      title="Click to toggle security overview or open BARQAI side panel"
    >
      <span className={`codefort-badge-dot ${verdictClass}`} />
      <span className="codefort-badge-label">CODEFORT:</span>
      <span className={`codefort-badge-verdict ${verdictClass}`}>{verdictText}</span>
      <span className="codefort-badge-score">({riskScore}/100)</span>

      {expanded && (
        <div
          className="codefort-badge-popover"
          onClick={(e) => e.stopPropagation()}
        >
          <div className="codefort-popover-header">
            <span className="codefort-popover-title">BARQAI SECURITY INTELLIGENCE</span>
            <span className={`codefort-popover-verdict ${verdictClass}`}>{verdictText}</span>
          </div>

          <p className="codefort-popover-desc">
            {summary?.summary?.why_it_matters || summary?.summary?.what_changed || explanation}
          </p>

          {summary?.summary?.evidence_observed && summary.summary.evidence_observed.length > 0 && (
            <div className="codefort-popover-evidence">
              <span className="codefort-popover-subtitle">Observed Evidence:</span>
              <ul>
                {summary.summary.evidence_observed.map((ev, i) => (
                  <li key={i}>{ev}</li>
                ))}
              </ul>
            </div>
          )}

          <div className="codefort-popover-actions">
            <button
              type="button"
              className="codefort-popover-btn primary"
              onClick={() => {
                if (onOpenSidePanel) {
                  onOpenSidePanel();
                } else if (typeof chrome !== "undefined" && chrome.runtime?.sendMessage) {
                  chrome.runtime.sendMessage({ type: "OPEN_SIDEPANEL" });
                }
              }}
            >
              Open BARQAI Side Panel ⚡
            </button>
            <a
              href="https://codefort-web.vercel.app/dashboard"
              target="_blank"
              rel="noreferrer"
              className="codefort-popover-link"
            >
              Dashboard ↗
            </a>
          </div>
        </div>
      )}
    </span>
  );
};

let activeRoot: ReactDOM.Root | null = null;

export function injectPRHeaderBadge(
  status: ExtensionPRStatusResponse | null,
  summary: ExtensionSummaryResponse | null,
  loading: boolean,
  error?: string | null
): boolean {
  // 1. Remove previous badge instance if present
  const existing = document.getElementById(BADGE_ROOT_ID);
  if (existing) {
    if (activeRoot) {
      activeRoot.unmount();
      activeRoot = null;
    }
    existing.remove();
  }

  // 2. Locate target element in GitHub PR header across GitHub responsive DOM layouts
  const target =
    document.querySelector(".gh-header-meta") ||
    document.querySelector(".gh-header-actions") ||
    document.querySelector(".gh-header-title") ||
    document.querySelector("#partial-discussion-header") ||
    document.querySelector("[data-testid='issue-metadata-fixed']") ||
    document.querySelector(".js-issue-title");

  if (!target) return false;

  // 3. Mount React Badge
  const container = document.createElement("span");
  container.id = BADGE_ROOT_ID;
  target.appendChild(container);

  activeRoot = ReactDOM.createRoot(container);
  activeRoot.render(
    <PRSecurityBadge
      status={status}
      summary={summary}
      loading={loading}
      error={error}
      onOpenSidePanel={() => {
        if (typeof chrome !== "undefined" && chrome.runtime?.sendMessage) {
          chrome.runtime.sendMessage({ type: "OPEN_SIDEPANEL" });
        }
      }}
    />
  );

  return true;
}

export function cleanupPRHeaderBadge(): void {
  if (activeRoot) {
    activeRoot.unmount();
    activeRoot = null;
  }
  const existing = document.getElementById(BADGE_ROOT_ID);
  if (existing) {
    existing.remove();
  }
}
