import React, { useEffect, useState } from "react";
import { parsePRUrl } from "../utils/github-url-parser";
import { getStoredConfig, setStoredConfig } from "../shared/storage";
import {
  ExtensionConfig,
  ExtensionMessage,
  ExtensionPRStatusResponse,
  ExtensionResponse,
} from "../shared/types";

export const Popup: React.FC = () => {
  const [config, setConfig] = useState<ExtensionConfig | null>(null);
  const [pairingToken, setPairingToken] = useState("");
  const [activePR, setActivePR] = useState<{ owner: string; repo: string; prNumber: number } | null>(null);
  const [prStatus, setPRStatus] = useState<ExtensionPRStatusResponse | null>(null);
  const [protectionActive, setProtectionActive] = useState(true);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    loadConfig();
    detectActiveTab();
  }, []);

  async function loadConfig() {
    const cfg = await getStoredConfig();
    setConfig(cfg);
  }

  async function detectActiveTab() {
    if (typeof chrome === "undefined" || !chrome.tabs?.query) {
      const mockPR = { owner: "codefort-sec", repo: "codefort-sec/barqai", prNumber: 42 };
      setActivePR(mockPR);
      fetchStatus(mockPR.repo, mockPR.prNumber);
      return;
    }

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.url) {
        const prInfo = parsePRUrl(tab.url);
        if (prInfo) {
          setActivePR(prInfo);
          fetchStatus(prInfo.repo, prInfo.prNumber);
        }
      }
    } catch {
      // Ignore tab query errors
    }
  }

  async function fetchStatus(repo: string, prNumber: number) {
    setLoading(true);
    setErrorMsg(null);
    try {
      const msg: ExtensionMessage = { type: "GET_PR_STATUS", repo, pr: prNumber };
      const res = await chrome.runtime.sendMessage<
        ExtensionMessage,
        ExtensionResponse<ExtensionPRStatusResponse>
      >(msg);

      if (res?.success) {
        setPRStatus(res.data);
      } else {
        setErrorMsg(res?.error?.message || "Failed to load PR scan");
      }
    } catch (err: any) {
      setErrorMsg(err.message || "Communication error with background worker");
    } finally {
      setLoading(false);
    }
  }

  async function handlePair() {
    if (!pairingToken.trim()) return;
    setLoading(true);
    setErrorMsg(null);
    try {
      const msg: ExtensionMessage = {
        type: "PAIR_WITH_TOKEN",
        pairingToken: pairingToken.trim(),
      };
      const res = await chrome.runtime.sendMessage<
        ExtensionMessage,
        ExtensionResponse<{ paired: boolean }>
      >(msg);

      if (!res?.success || !res.data.paired) {
        setErrorMsg(res?.error?.message || "Invalid or expired token");
      } else {
        setPairingToken("");
        await loadConfig();
        if (activePR) {
          fetchStatus(activePR.repo, activePR.prNumber);
        }
      }
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to pair with token");
    } finally {
      setLoading(false);
    }
  }

  async function handleDisconnect() {
    setLoading(true);
    try {
      await chrome.runtime.sendMessage({ type: "DISCONNECT" });
      await setStoredConfig({ token: null, paired: false });
      await loadConfig();
      setPRStatus(null);
    } catch {
      // Clear local config as fallback
      await setStoredConfig({ token: null, paired: false });
      await loadConfig();
    } finally {
      setLoading(false);
    }
  }

  async function handleOpenSidePanel() {
    try {
      if (typeof chrome !== "undefined") {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab?.windowId && (chrome as any).sidePanel?.open) {
          await (chrome as any).sidePanel.open({ windowId: tab.windowId });
          window.close();
          return;
        }
      }
    } catch {
      // Fallback: send message to background
    }

    try {
      await chrome.runtime.sendMessage({ type: "OPEN_SIDEPANEL" });
      window.close();
    } catch {
      // If sidePanel open fails, open the standalone panel URL in a new tab
      if (typeof chrome !== "undefined" && chrome.tabs?.create) {
        chrome.tabs.create({ url: chrome.runtime.getURL("sidepanel.html") });
        window.close();
      }
    }
  }

  const isPaired = Boolean(config?.paired);
  const verdict = prStatus?.verdict || "PASS";
  const riskScore = prStatus?.risk_score ?? 0;

  return (
    <div style={{
      width: "340px",
      backgroundColor: "#0d0f0d",
      color: "#e2e8f0",
      fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
      padding: "16px",
      display: "flex",
      flexDirection: "column",
      gap: "14px",
      boxSizing: "border-box",
    }}>
      {/* Header Brand */}
      <div style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        borderBottom: "1px solid #222622",
        paddingBottom: "10px",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <div style={{
            width: "14px",
            height: "14px",
            backgroundColor: "#d7ff35",
            clipPath: "polygon(0 0, 100% 0, 80% 100%, 0% 100%)",
          }} />
          <span style={{ fontSize: "14px", fontWeight: 900, color: "#d7ff35", letterSpacing: "1px" }}>
            CODEFORT GUARD
          </span>
        </div>
        <span style={{
          fontSize: "9px",
          fontWeight: 800,
          backgroundColor: "#182018",
          border: "1px solid #2a352a",
          padding: "2px 6px",
          color: "#888",
        }}>
          v1.0.0
        </span>
      </div>

      {/* Connection & Protection Status Bar */}
      <div style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        backgroundColor: "#131713",
        border: "1px solid #222622",
        padding: "8px 12px",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "11px" }}>
          <span style={{
            width: "8px",
            height: "8px",
            borderRadius: "50%",
            backgroundColor: isPaired ? "#00FF66" : "#FFAA00",
            display: "inline-block",
            boxShadow: isPaired ? "0 0 8px rgba(0,255,102,0.4)" : "none",
          }} />
          <span style={{ fontWeight: 800, color: isPaired ? "#00FF66" : "#FFAA00" }}>
            {isPaired ? "PAIRED" : "UNPAIRED"}
          </span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "10px" }}>
          <span style={{ color: "#888" }}>SHIELD:</span>
          <button
            onClick={() => setProtectionActive(!protectionActive)}
            style={{
              background: protectionActive ? "rgba(215,255,53,0.15)" : "#222",
              border: `1px solid ${protectionActive ? "#d7ff35" : "#444"}`,
              color: protectionActive ? "#d7ff35" : "#777",
              fontWeight: 800,
              fontSize: "9px",
              padding: "2px 6px",
              cursor: "pointer",
            }}
          >
            {protectionActive ? "ACTIVE" : "PAUSED"}
          </button>
        </div>
      </div>

      {/* Pairing Token Form if Unpaired */}
      {!isPaired && (
        <div style={{
          border: "1px solid #FFAA00",
          backgroundColor: "rgba(255,170,0,0.05)",
          padding: "12px",
          display: "flex",
          flexDirection: "column",
          gap: "8px",
        }}>
          <div style={{ fontSize: "10px", fontWeight: 800, color: "#FFAA00", letterSpacing: "0.5px" }}>
            ONE-TIME PAIRING CODE REQUIRED
          </div>
          <div style={{ fontSize: "10px", color: "#bbb", lineHeight: 1.4 }}>
            Go to CODEFORT Dashboard &gt; Settings &gt; Generate Pairing Token, then paste below:
          </div>

          <div style={{ display: "flex", gap: "6px" }}>
            <input
              type="text"
              value={pairingToken}
              onChange={(e) => setPairingToken(e.target.value)}
              placeholder="pair_xxxxxxxx"
              style={{
                flex: 1,
                backgroundColor: "#080a08",
                border: "1px solid #333",
                color: "#fff",
                fontSize: "11px",
                padding: "6px 8px",
                fontFamily: "inherit",
              }}
            />
            <button
              onClick={handlePair}
              disabled={loading || !pairingToken.trim()}
              style={{
                backgroundColor: "#d7ff35",
                color: "#0d0f0d",
                fontWeight: 900,
                border: "none",
                padding: "6px 12px",
                fontSize: "10px",
                cursor: "pointer",
              }}
            >
              {loading ? "..." : "PAIR"}
            </button>
          </div>
        </div>
      )}

      {/* Current GitHub Context */}
      {activePR ? (
        <div style={{
          border: "1px solid #222622",
          backgroundColor: "#131713",
          padding: "10px",
          display: "flex",
          flexDirection: "column",
          gap: "6px",
        }}>
          <div style={{ fontSize: "9px", color: "#888", textTransform: "uppercase" }}>
            Active Repository &amp; PR
          </div>
          <div style={{ fontSize: "12px", fontWeight: 800, color: "#fff" }}>
            {activePR.repo} <span style={{ color: "#d7ff35" }}>#{activePR.prNumber}</span>
          </div>

          {prStatus && (
            <div style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginTop: "4px",
              paddingTop: "6px",
              borderTop: "1px solid #1f251f",
              fontSize: "10px",
            }}>
              <span>Status: <strong style={{
                color: verdict === "BLOCKED" ? "#FF0055" : verdict === "REVIEW_REQUIRED" ? "#FFAA00" : "#00FF66"
              }}>{verdict}</strong></span>
              <span>Risk: <strong>{riskScore}/100</strong></span>
            </div>
          )}
        </div>
      ) : (
        <div style={{ fontSize: "10px", color: "#777", textAlign: "center", padding: "6px" }}>
          Navigate to any GitHub Pull Request to view inline analysis.
        </div>
      )}

      {errorMsg && (
        <div style={{ fontSize: "10px", color: "#FF0055", backgroundColor: "rgba(255,0,85,0.1)", padding: "6px", border: "1px solid #FF0055" }}>
          {errorMsg}
        </div>
      )}

      {/* Main Action: Open BARQAI Side Panel */}
      <button
        id="open-panel"
        onClick={handleOpenSidePanel}
        style={{
          backgroundColor: "#d7ff35",
          color: "#0d0f0d",
          border: "none",
          fontWeight: 900,
          fontSize: "12px",
          padding: "10px",
          cursor: "pointer",
          letterSpacing: "0.5px",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          gap: "8px",
        }}
      >
        <span>⚡ OPEN BARQAI PANEL</span>
        <span>→</span>
      </button>

      {/* Bottom Actions */}
      <div style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        borderTop: "1px solid #222622",
        paddingTop: "8px",
        fontSize: "10px",
      }}>
        <a
          href="https://codefort-web.vercel.app/dashboard"
          target="_blank"
          rel="noreferrer"
          style={{ color: "#888", textDecoration: "none" }}
          onMouseEnter={(e) => ((e.target as HTMLElement).style.color = "#d7ff35")}
          onMouseLeave={(e) => ((e.target as HTMLElement).style.color = "#888")}
        >
          Open Dashboard ↗
        </a>

        {isPaired && (
          <button
            onClick={handleDisconnect}
            style={{
              background: "none",
              border: "none",
              color: "#666",
              fontSize: "10px",
              cursor: "pointer",
              padding: 0,
            }}
            onMouseEnter={(e) => ((e.target as HTMLElement).style.color = "#FF0055")}
            onMouseLeave={(e) => ((e.target as HTMLElement).style.color = "#666")}
          >
            Disconnect
          </button>
        )}
      </div>
    </div>
  );
};
