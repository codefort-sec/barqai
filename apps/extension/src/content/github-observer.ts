/**
 * CODEFORT Guard - GitHub SPA & Diff Observer
 * Reliably detects GitHub Turbo/SPA navigations, PR page loading, and dynamic diff rendering.
 */

import { parsePRUrl } from "../utils/github-url-parser";
import { injectPRHeaderBadge, cleanupPRHeaderBadge } from "./pr-header-injector";
import { injectDiffWarnings, cleanupDiffWarnings } from "./diff-injector";
import {
  ExtensionLineFinding,
  ExtensionMessage,
  ExtensionPRStatusResponse,
  ExtensionResponse,
  ExtensionSummaryResponse,
} from "../shared/types";

export class GitHubObserver {
  private currentPRKey: string | null = null;
  private diffObserver: MutationObserver | null = null;
  private urlObserver: MutationObserver | null = null;
  private lastUrl: string = "";
  private retryTimer: any = null;
  private isProcessing: boolean = false;

  constructor() {
    this.handleNavigation = this.handleNavigation.bind(this);
  }

  public start(): void {
    this.lastUrl = window.location.href;

    // Initial check
    this.handleNavigation();

    // Listen for modern GitHub Turbo events
    document.addEventListener("turbo:render", this.handleNavigation);
    document.addEventListener("turbo:load", this.handleNavigation);
    document.addEventListener("pjax:end", this.handleNavigation);
    window.addEventListener("popstate", this.handleNavigation);

    // Fallback URL observer for client-side routing changes
    this.urlObserver = new MutationObserver(() => {
      if (window.location.href !== this.lastUrl) {
        this.lastUrl = window.location.href;
        this.handleNavigation();
      }
    });

    this.urlObserver.observe(document.body, { childList: true, subtree: true });
  }

  public stop(): void {
    document.removeEventListener("turbo:render", this.handleNavigation);
    document.removeEventListener("turbo:load", this.handleNavigation);
    document.removeEventListener("pjax:end", this.handleNavigation);
    window.removeEventListener("popstate", this.handleNavigation);

    if (this.urlObserver) {
      this.urlObserver.disconnect();
      this.urlObserver = null;
    }

    if (this.diffObserver) {
      this.diffObserver.disconnect();
      this.diffObserver = null;
    }

    if (this.retryTimer) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }

    cleanupPRHeaderBadge();
    cleanupDiffWarnings();
    this.currentPRKey = null;
  }

  public async handleNavigation(): Promise<void> {
    const prInfo = parsePRUrl(window.location.href);

    if (!prInfo) {
      if (this.currentPRKey) {
        cleanupPRHeaderBadge();
        cleanupDiffWarnings();
        if (this.diffObserver) {
          this.diffObserver.disconnect();
          this.diffObserver = null;
        }
        this.currentPRKey = null;
      }
      return;
    }

    const prKey = `${prInfo.repo}#${prInfo.pr}`;
    this.currentPRKey = prKey;

    await this.scanAndInject(prInfo.repo, prInfo.pr);
  }

  public async scanAndInject(repo: string, pr: number, retryCount = 0): Promise<void> {
    if (this.retryTimer) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }

    // Mount loading state into header badge
    const badgeMounted = injectPRHeaderBadge(null, null, true, null);
    if (!badgeMounted && retryCount < 10) {
      this.retryTimer = setTimeout(() => {
        this.scanAndInject(repo, pr, retryCount + 1);
      }, 300);
      return;
    }

    if (this.isProcessing) return;
    this.isProcessing = true;

    try {
      const statusMsg: ExtensionMessage = { type: "GET_PR_STATUS", repo, pr };
      const summaryMsg: ExtensionMessage = { type: "GET_PR_SUMMARY", repo, pr };
      const findingsMsg: ExtensionMessage = { type: "GET_PR_FINDINGS", repo, pr };

      const [statusRes, summaryRes, findingsRes] = await Promise.all([
        chrome.runtime.sendMessage<ExtensionMessage, ExtensionResponse<ExtensionPRStatusResponse>>(statusMsg),
        chrome.runtime.sendMessage<ExtensionMessage, ExtensionResponse<ExtensionSummaryResponse>>(summaryMsg),
        chrome.runtime.sendMessage<
          ExtensionMessage,
          ExtensionResponse<{ findings: ExtensionLineFinding[] }>
        >(findingsMsg),
      ]);

      if (!statusRes.success) {
        injectPRHeaderBadge(
          null,
          null,
          false,
          statusRes.error?.message || "Failed to fetch scan data"
        );
        return;
      }

      // Update PR Header Badge
      injectPRHeaderBadge(
        statusRes.data,
        summaryRes.success ? summaryRes.data : null,
        false,
        null
      );

      // Inject Inline Diff Warnings if findings exist
      const findings = findingsRes.success && findingsRes.data?.findings ? findingsRes.data.findings : [];
      if (findings.length > 0) {
        injectDiffWarnings(repo, pr, findings);
        this.observeDiffTree(repo, pr, findings);
      }
    } catch (err: any) {
      injectPRHeaderBadge(
        null,
        null,
        false,
        err.message || "Failed to communicate with CODEFORT service"
      );
    } finally {
      this.isProcessing = false;
    }
  }

  private observeDiffTree(repo: string, pr: number, findings: ExtensionLineFinding[]): void {
    if (this.diffObserver) {
      this.diffObserver.disconnect();
    }

    let diffDebounce: any = null;

    this.diffObserver = new MutationObserver((mutations) => {
      let shouldReinject = false;

      for (const m of mutations) {
        if (m.addedNodes.length > 0) {
          for (let i = 0; i < m.addedNodes.length; i++) {
            const node = m.addedNodes[i] as HTMLElement;
            if (node.nodeType === Node.ELEMENT_NODE) {
              if (
                node.classList?.contains("file") ||
                node.classList?.contains("diff-table") ||
                node.querySelector?.("div[data-path], table.diff-table")
              ) {
                shouldReinject = true;
                break;
              }
            }
          }
        }
        if (shouldReinject) break;
      }

      if (shouldReinject) {
        if (diffDebounce) clearTimeout(diffDebounce);
        diffDebounce = setTimeout(() => {
          injectDiffWarnings(repo, pr, findings);
        }, 150);
      }
    });

    const diffContainer =
      document.querySelector("#files") ||
      document.querySelector(".js-diff-progressive-container") ||
      document.body;

    this.diffObserver.observe(diffContainer, { childList: true, subtree: true });
  }
}
