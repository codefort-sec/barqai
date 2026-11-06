/**
 * CODEFORT Guard - Content Script Entrypoint
 * Injects security status badges and diff warnings into GitHub Pull Requests.
 */

import "./content.css";
import { GitHubObserver } from "./github-observer";

const observer = new GitHubObserver();
observer.start();

// Listen for background service worker awakening messages
if (typeof chrome !== "undefined" && chrome.runtime?.onMessage) {
  chrome.runtime.onMessage.addListener((message: any) => {
    if (message.type === "AWAKE_PR_SCAN") {
      observer.handleNavigation();
    }
  });
}
