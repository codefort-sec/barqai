/**
 * CODEFORT Guard - Inline Diff Warnings & Remediation Injector
 * Injects non-intrusive warning banners and 1-click patch drawers into GitHub PR diff views.
 */

import {
  ExtensionLineFinding,
  ExtensionMessage,
  ExtensionRemediationResponse,
  ExtensionResponse,
} from "../shared/types";

export const WARNING_ROW_CLASS = "codefort-diff-warning-row";

export function injectDiffWarnings(
  repo: string,
  pr: number,
  findings: ExtensionLineFinding[]
): void {
  if (!findings || findings.length === 0) return;

  // Remove stale warning rows
  document.querySelectorAll(`.${WARNING_ROW_CLASS}`).forEach((el) => el.remove());

  findings.forEach((finding) => {
    // 1. Locate matching file box in GitHub diff view
    const fileBoxes = document.querySelectorAll(
      `div[data-path*="${finding.file_path}"], div[data-tagsearch-path*="${finding.file_path}"], div.file[data-file-type]`
    );

    fileBoxes.forEach((fileBox) => {
      // 2. Locate matching line number cell in diff table
      const lineCell = fileBox.querySelector(
        `td[data-line-number="${finding.line_start}"]`
      );
      const row = lineCell?.closest("tr");

      if (row && !row.nextElementSibling?.classList.contains(WARNING_ROW_CLASS)) {
        const warningRow = document.createElement("tr");
        warningRow.className = WARNING_ROW_CLASS;

        const cell = document.createElement("td");
        cell.colSpan = 10;

        const box = document.createElement("div");
        box.className = "codefort-diff-warning-box";

        // Severity Tag
        const tag = document.createElement("span");
        tag.className = `codefort-diff-warning-tag ${finding.severity.toLowerCase()}`;
        tag.textContent = finding.severity;
        box.appendChild(tag);

        // Content Details
        const contentDiv = document.createElement("div");
        contentDiv.className = "codefort-diff-warning-content";

        const titleDiv = document.createElement("div");
        titleDiv.className = "codefort-diff-warning-title";
        titleDiv.textContent = `🛡 ${finding.title} (${finding.rule_id})`;
        contentDiv.appendChild(titleDiv);

        if (finding.recommendation) {
          const recomDiv = document.createElement("div");
          recomDiv.className = "codefort-diff-warning-recom";
          recomDiv.textContent = finding.recommendation;
          contentDiv.appendChild(recomDiv);
        }

        box.appendChild(contentDiv);

        // Fix / Inspect with BARQAI Button
        const fixBtn = document.createElement("button");
        fixBtn.type = "button";
        fixBtn.className = "codefort-diff-fix-btn";
        fixBtn.textContent = "⚡ Fix with BARQAI";

        fixBtn.onclick = async (e) => {
          e.preventDefault();
          e.stopPropagation();

          const existingDrawer = box.querySelector(".codefort-inline-remediation-drawer");
          if (existingDrawer) {
            existingDrawer.remove();
            fixBtn.textContent = "⚡ Fix with BARQAI";
            return;
          }

          fixBtn.textContent = "Synthesizing Fix...";
          try {
            const remRes = await chrome.runtime.sendMessage<
              ExtensionMessage,
              ExtensionResponse<ExtensionRemediationResponse>
            >({ type: "GET_PR_REMEDIATION", repo, pr });

            if (!remRes.success || !remRes.data) {
              fixBtn.textContent = "No Fix Available";
              return;
            }

            const data = remRes.data;
            const proposal =
              data.proposals?.find(
                (p) => p.finding_id === finding.id || p.rule_id === finding.rule_id
              ) || data.proposals?.[0];

            if (!proposal) {
              fixBtn.textContent = "No Patch Found";
              return;
            }

            fixBtn.textContent = "Hide Fix";

            // Drawer container
            const drawer = document.createElement("div");
            drawer.className = "codefort-inline-remediation-drawer";

            const header = document.createElement("div");
            header.className = "codefort-drawer-header";
            header.innerHTML = `
              <span style="font-weight:700;color:#d7ff35;font-size:10px;">BARQAI VERIFIED FIX (${proposal.rule_id})</span>
              <span class="codefort-verified-pill">${proposal.verification_status || "verified"}</span>
            `;
            drawer.appendChild(header);

            // Side-by-Side Code Grid
            const grid = document.createElement("div");
            grid.className = "codefort-drawer-code-grid";

            const beforeBox = document.createElement("div");
            beforeBox.className = "codefort-code-before";
            beforeBox.textContent = `// Original Code\n${proposal.original_code}`;
            grid.appendChild(beforeBox);

            const afterBox = document.createElement("div");
            afterBox.className = "codefort-code-after";
            afterBox.textContent = `// BARQAI Corrected Code\n${proposal.suggested_code}`;
            grid.appendChild(afterBox);

            drawer.appendChild(grid);

            // Action Buttons
            const actions = document.createElement("div");
            actions.className = "codefort-drawer-actions";

            const copyBtn = document.createElement("button");
            copyBtn.type = "button";
            copyBtn.className = "codefort-copy-fix-btn";
            copyBtn.textContent = "Copy Patch";
            copyBtn.onclick = () => {
              navigator.clipboard.writeText(proposal.unified_diff || data.clean_patch || "");
              copyBtn.textContent = "Copied!";
              setTimeout(() => {
                copyBtn.textContent = "Copy Patch";
              }, 2000);
            };
            actions.appendChild(copyBtn);

            const applyBtn = document.createElement("button");
            applyBtn.type = "button";
            applyBtn.className = "codefort-apply-fix-btn";
            applyBtn.textContent = "Apply Fix to PR Branch ↗";
            applyBtn.onclick = async () => {
              applyBtn.disabled = true;
              applyBtn.textContent = "Applying...";
              try {
                const applyRes = await chrome.runtime.sendMessage<
                  ExtensionMessage,
                  ExtensionResponse<{ status: string; message: string }>
                >({ type: "APPLY_PR_REMEDIATION", repo, pr });

                if (applyRes.success) {
                  applyBtn.textContent = "✓ Fix Applied to Branch!";
                  applyBtn.style.background = "#00FF66";
                  applyBtn.style.color = "#070807";
                } else {
                  applyBtn.textContent = "Failed to Apply";
                  applyBtn.disabled = false;
                }
              } catch {
                applyBtn.textContent = "Error Applying";
                applyBtn.disabled = false;
              }
            };
            actions.appendChild(applyBtn);

            drawer.appendChild(actions);
            contentDiv.appendChild(drawer);
          } catch {
            fixBtn.textContent = "Fix Error";
          }
        };

        box.appendChild(fixBtn);
        cell.appendChild(box);
        warningRow.appendChild(cell);
        row.after(warningRow);
      }
    });
  });
}

export function cleanupDiffWarnings(): void {
  document.querySelectorAll(`.${WARNING_ROW_CLASS}`).forEach((el) => el.remove());
}
