import React, { useEffect, useState } from "react";
import { parsePRUrl } from "../utils/github-url-parser";
import { getStoredConfig } from "../shared/storage";
import {
  ExtensionConfig,
  ExtensionLineFinding,
  ExtensionMessage,
  ExtensionPRStatusResponse,
  ExtensionRemediationResponse,
  ExtensionResponse,
  ExtensionSummaryResponse,
} from "../shared/types";

export const SidePanel: React.FC = () => {
  const [config, setConfig] = useState<ExtensionConfig | null>(null);
  const [activePR, setActivePR] = useState<{ owner: string; repo: string; prNumber: number } | null>(null);
  const [status, setStatus] = useState<ExtensionPRStatusResponse | null>(null);
  const [summary, setSummary] = useState<ExtensionSummaryResponse | null>(null);
  const [findings, setFindings] = useState<ExtensionLineFinding[]>([]);
  const [remediation, setRemediation] = useState<ExtensionRemediationResponse | null>(null);
  const [showPatch, setShowPatch] = useState(false);
  const [loading, setLoading] = useState(false);
  const [applyState, setApplyState] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    loadConfig();
    detectActiveTab();

    // Listen for tab activation changes to track current PR
    if (typeof chrome !== "undefined" && chrome.tabs?.onActivated) {
      const listener = () => detectActiveTab();
      chrome.tabs.onActivated.addListener(listener);
      return () => {
        chrome.tabs.onActivated.removeListener(listener);
      };
    }
  }, []);

  async function loadConfig() {
    const cfg = await getStoredConfig();
    setConfig(cfg);
  }

  async function detectActiveTab() {
    if (typeof chrome === "undefined" || !chrome.tabs?.query) {
      // Mock PR for development preview
      const mockPR = { owner: "codefort-sec", repo: "codefort-sec/barqai", prNumber: 42 };
      setActivePR(mockPR);
      fetchPRData(mockPR.repo, mockPR.prNumber);
      return;
    }

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.url) {
        const prInfo = parsePRUrl(tab.url);
        if (prInfo) {
          setActivePR(prInfo);
          fetchPRData(prInfo.repo, prInfo.prNumber);
        } else {
          setActivePR(null);
        }
      }
    } catch {
      // Ignore tab query errors
    }
  }

  async function fetchPRData(repo: string, prNumber: number) {
    setLoading(true);
    setErrorMsg(null);
    try {
      const statusMsg: ExtensionMessage = { type: "GET_PR_STATUS", repo, pr: prNumber };
      const summaryMsg: ExtensionMessage = { type: "GET_PR_SUMMARY", repo, pr: prNumber };
      const findingsMsg: ExtensionMessage = { type: "GET_PR_FINDINGS", repo, pr: prNumber };
      const remediationMsg: ExtensionMessage = { type: "GET_PR_REMEDIATION", repo, pr: prNumber };

      const [statusRes, summaryRes, findingsRes, remRes] = await Promise.all([
        chrome.runtime.sendMessage<ExtensionMessage, ExtensionResponse<ExtensionPRStatusResponse>>(statusMsg),
        chrome.runtime.sendMessage<ExtensionMessage, ExtensionResponse<ExtensionSummaryResponse>>(summaryMsg),
        chrome.runtime.sendMessage<ExtensionMessage, ExtensionResponse<{ findings: ExtensionLineFinding[] }>>(findingsMsg),
        chrome.runtime.sendMessage<ExtensionMessage, ExtensionResponse<ExtensionRemediationResponse>>(remediationMsg),
      ]);

      if (statusRes?.success) setStatus(statusRes.data);
      if (summaryRes?.success) setSummary(summaryRes.data);
      if (findingsRes?.success) setFindings(findingsRes.data?.findings || []);
      if (remRes?.success) setRemediation(remRes.data);
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to load security findings");
    } finally {
      setLoading(false);
    }
  }

  async function handleApplyFix() {
    if (!activePR) return;
    setApplyState("applying");
    try {
      const msg: ExtensionMessage = {
        type: "APPLY_PR_REMEDIATION",
        repo: activePR.repo,
        pr: activePR.prNumber,
      };
      const res = await chrome.runtime.sendMessage<
        ExtensionMessage,
        ExtensionResponse<{ status: string; message: string }>
      >(msg);

      if (res.success) {
        setApplyState("applied");
        setTimeout(() => setApplyState(null), 4000);
      } else {
        setApplyState("error");
      }
    } catch {
      setApplyState("error");
    }
  }

  const verdict = status?.verdict || "PASS";
  const riskScore = status?.risk_score ?? (verdict === "BLOCKED" ? 85 : verdict === "REVIEW_REQUIRED" ? 45 : 0);

  const verdictColors = {
    PASS: { border: "#00FF66", bg: "rgba(0,255,102,0.1)", text: "#00FF66" },
    REVIEW_REQUIRED: { border: "#FFAA00", bg: "rgba(255,170,0,0.1)", text: "#FFAA00" },
    BLOCKED: { border: "#FF0055", bg: "rgba(255,0,85,0.1)", text: "#FF0055" },
    SCAN_PENDING: { border: "#00E5FF", bg: "rgba(0,229,255,0.1)", text: "#00E5FF" },
    SCAN_ERROR: { border: "#888888", bg: "rgba(136,136,136,0.1)", text: "#888888" },
  };

  const currentTheme = verdictColors[verdict as keyof typeof verdictColors] || verdictColors.PASS;

  return (
    <div style={{
      minHeight: "100vh",
      backgroundColor: "#0d0f0d",
      color: "#e2e8f0",
      fontFamily: "'JetBrains Mono', 'Fira Code', Menlo, Consolas, monospace",
      padding: "16px",
      display: "flex",
      flexDirection: "column",
      gap: "16px",
      boxSizing: "border-box",
    }}>
      {/* Top Header */}
      <div style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        borderBottom: "1px solid #222622",
        paddingBottom: "12px",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <div style={{
            width: "12px",
            height: "12px",
            backgroundColor: "#d7ff35",
            clipPath: "polygon(0 0, 100% 0, 80% 100%, 0% 100%)",
          }} />
          <span style={{ fontSize: "13px", fontWeight: 900, color: "#d7ff35", letterSpacing: "1px" }}>
            CODEFORT_
          </span>
          <span style={{ fontSize: "11px", color: "#666" }}>// BARQAI</span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "10px" }}>
          <span style={{
            width: "6px",
            height: "6px",
            borderRadius: "50%",
            backgroundColor: config?.paired ? "#00FF66" : "#FFAA00",
            display: "inline-block",
          }} />
          <span style={{ color: config?.paired ? "#00FF66" : "#FFAA00", fontWeight: 700 }}>
            {config?.paired ? "CONNECTED" : "UNPAIRED"}
          </span>
        </div>
      </div>

      {/* Target PR Card */}
      {activePR ? (
        <div style={{
          border: "1px solid #222622",
          backgroundColor: "#131713",
          padding: "12px",
          display: "flex",
          flexDirection: "column",
          gap: "8px",
        }}>
          <div style={{ fontSize: "9px", color: "#888", textTransform: "uppercase", letterSpacing: "1px" }}>
            Target GitHub Pull Request
          </div>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <span style={{ fontSize: "13px", fontWeight: 800, color: "#fff" }}>
              {activePR.repo} <span style={{ color: "#d7ff35" }}>#{activePR.prNumber}</span>
            </span>
            <button
              onClick={() => fetchPRData(activePR.repo, activePR.prNumber)}
              disabled={loading}
              style={{
                background: "none",
                border: "1px solid #333",
                color: "#bbb",
                fontSize: "10px",
                padding: "3px 8px",
                cursor: "pointer",
              }}
            >
              {loading ? "Scanning..." : "↻ Refresh"}
            </button>
          </div>
        </div>
      ) : (
        <div style={{
          border: "1px dashed #333",
          padding: "20px",
          textAlign: "center",
          color: "#888",
          fontSize: "11px",
        }}>
          No GitHub Pull Request detected in active tab.
          <br />
          Open a pull request on GitHub to inspect live forensics.
        </div>
      )}

      {/* Risk Score & Verdict HUD */}
      {activePR && (
        <div style={{
          border: `1px solid ${currentTheme.border}`,
          backgroundColor: currentTheme.bg,
          padding: "14px",
          display: "flex",
          flexDirection: "column",
          gap: "10px",
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <div style={{ fontSize: "9px", color: "#aaa", textTransform: "uppercase", letterSpacing: "1px" }}>
                Risk Classification
              </div>
              <div style={{ fontSize: "20px", fontWeight: 900, color: currentTheme.text }}>
                {verdict.replace("_REQUIRED", "")}
              </div>
            </div>
            <div style={{ textAlign: "right" }}>
              <div style={{ fontSize: "9px", color: "#aaa", textTransform: "uppercase", letterSpacing: "1px" }}>
                Risk Score
              </div>
              <div style={{ fontSize: "20px", fontWeight: 900, color: "#fff" }}>
                {riskScore}<span style={{ fontSize: "12px", color: "#777" }}>/100</span>
              </div>
            </div>
          </div>

          {/* Progress Meter Bar */}
          <div style={{ width: "100%", height: "6px", backgroundColor: "#000", overflow: "hidden" }}>
            <div style={{
              width: `${Math.min(100, Math.max(5, riskScore))}%`,
              height: "100%",
              backgroundColor: currentTheme.text,
              transition: "width 0.5s ease",
            }} />
          </div>
        </div>
      )}

      {/* Security Findings Section */}
      {findings.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
          <div style={{
            fontSize: "10px",
            fontWeight: 800,
            color: "#d7ff35",
            textTransform: "uppercase",
            letterSpacing: "1px",
          }}>
            SECURITY FINDINGS ({findings.length})
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            {findings.map((f, i) => (
              <div
                key={f.id || i}
                style={{
                  border: "1px solid #222622",
                  backgroundColor: "#131713",
                  padding: "10px",
                  display: "flex",
                  flexDirection: "column",
                  gap: "6px",
                  fontSize: "11px",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <span style={{ fontWeight: 800, color: "#fff" }}>{f.title}</span>
                  <span style={{
                    fontSize: "9px",
                    fontWeight: 900,
                    padding: "2px 6px",
                    border: `1px solid ${f.severity === "CRITICAL" || f.severity === "HIGH" ? "#FF0055" : "#FFAA00"}`,
                    backgroundColor: f.severity === "CRITICAL" || f.severity === "HIGH" ? "rgba(255,0,85,0.15)" : "rgba(255,170,0,0.15)",
                    color: f.severity === "CRITICAL" || f.severity === "HIGH" ? "#FF0055" : "#FFAA00",
                    textTransform: "uppercase",
                  }}>
                    {f.severity}
                  </span>
                </div>

                <div style={{ fontSize: "10px", color: "#888" }}>
                  File: <span style={{ color: "#d7ff35" }}>{f.file_path}:{f.line_start}</span>
                </div>

                {f.recommendation && (
                  <div style={{ fontSize: "10px", color: "#bbb", backgroundColor: "#0b0d0b", padding: "6px", borderLeft: "2px solid #d7ff35" }}>
                    {f.recommendation}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* BARQAI Security Intelligence Explanation */}
      {summary?.summary && (
        <div style={{
          border: "1px solid #222622",
          backgroundColor: "#131713",
          padding: "12px",
          display: "flex",
          flexDirection: "column",
          gap: "8px",
        }}>
          <div style={{ fontSize: "10px", fontWeight: 800, color: "#d7ff35", textTransform: "uppercase", letterSpacing: "1px" }}>
            BARQAI EXPLANATION
          </div>
          <p style={{ fontSize: "11px", color: "#ccc", margin: 0, lineHeight: 1.5 }}>
            {summary.summary.why_it_matters || summary.summary.what_changed}
          </p>

          {summary.summary.evidence_observed?.length > 0 && (
            <div style={{ marginTop: "6px" }}>
              <div style={{ fontSize: "9px", color: "#777", textTransform: "uppercase", marginBottom: "4px" }}>
                Telemetry Evidence
              </div>
              <ul style={{ margin: 0, paddingLeft: "16px", fontSize: "10px", color: "#aaa" }}>
                {summary.summary.evidence_observed.map((ev, idx) => (
                  <li key={idx} style={{ marginBottom: "2px" }}>{ev}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Remediation Patch Section */}
      {remediation && remediation.proposals?.length > 0 && (
        <div style={{
          border: "1px solid #334",
          backgroundColor: "#101419",
          padding: "12px",
          display: "flex",
          flexDirection: "column",
          gap: "10px",
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: "10px", fontWeight: 800, color: "#00E5FF", letterSpacing: "1px" }}>
              1-CLICK REMEDIATION
            </span>
            <span style={{
              fontSize: "9px",
              padding: "1px 5px",
              border: "1px solid #00FF66",
              color: "#00FF66",
              fontWeight: 700,
            }}>
              VERIFIED
            </span>
          </div>

          <button
            onClick={() => setShowPatch(!showPatch)}
            style={{
              background: "#182028",
              border: "1px solid #00E5FF",
              color: "#00E5FF",
              fontSize: "11px",
              fontWeight: 800,
              padding: "6px 12px",
              cursor: "pointer",
              textAlign: "center",
            }}
          >
            {showPatch ? "Hide Verified Patch" : "⚡ Preview Clean Patch"}
          </button>

          {showPatch && (
            <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
              <pre style={{
                background: "#080b0e",
                border: "1px solid #222",
                padding: "8px",
                fontSize: "10px",
                color: "#aae",
                overflowX: "auto",
                whiteSpace: "pre-wrap",
                margin: 0,
              }}>
                {remediation.proposals[0].unified_diff || remediation.clean_patch || remediation.proposals[0].suggested_code}
              </pre>

              <button
                onClick={handleApplyFix}
                disabled={applyState === "applying" || applyState === "applied"}
                style={{
                  background: applyState === "applied" ? "#00FF66" : "#d7ff35",
                  border: "none",
                  color: "#0d0f0d",
                  fontSize: "11px",
                  fontWeight: 900,
                  padding: "8px 12px",
                  cursor: applyState === "applied" ? "default" : "pointer",
                }}
              >
                {applyState === "applying"
                  ? "Applying to branch..."
                  : applyState === "applied"
                  ? "✓ Applied to Branch!"
                  : "Apply Fix to PR Branch ↗"}
              </button>
            </div>
          )}
        </div>
      )}

      {/* Footer Navigation Actions */}
      <div style={{
        marginTop: "auto",
        borderTop: "1px solid #222622",
        paddingTop: "12px",
        display: "flex",
        flexDirection: "column",
        gap: "8px",
      }}>
        <div style={{ display: "flex", gap: "8px" }}>
          <a
            href="https://codefort-web.vercel.app/chat"
            target="_blank"
            rel="noreferrer"
            style={{
              flex: 1,
              backgroundColor: "rgba(215,255,53,0.1)",
              border: "1px solid #d7ff35",
              color: "#d7ff35",
              fontSize: "10px",
              fontWeight: 800,
              padding: "7px 10px",
              textAlign: "center",
              textDecoration: "none",
            }}
          >
            💬 Chat with BARQAI
          </a>
          <a
            href="https://codefort-web.vercel.app/dashboard"
            target="_blank"
            rel="noreferrer"
            style={{
              flex: 1,
              backgroundColor: "#181d18",
              border: "1px solid #333",
              color: "#ccc",
              fontSize: "10px",
              fontWeight: 800,
              padding: "7px 10px",
              textAlign: "center",
              textDecoration: "none",
            }}
          >
            Dashboard ↗
          </a>
        </div>

        <div style={{ fontSize: "9px", color: "#555", textAlign: "center" }}>
          CODEFORT Guard v1.0.0 // Zero-Trust PR Defense
        </div>
      </div>
    </div>
  );
};
