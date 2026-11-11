/**
 * GitHub Pull Request URL Parser
 * Extracts repository owner, repository name, and PR number.
 */

export interface PRInfo {
  owner: string;
  repo: string;
  prNumber: number;
  pr: number;
}

export function parsePRUrl(url?: string | null): PRInfo | null {
  if (!url) return null;
  try {
    const parsedUrl = new URL(url);
    if (parsedUrl.hostname !== "github.com" && !parsedUrl.hostname.endsWith(".github.com")) {
      return null;
    }
    const match = parsedUrl.pathname.match(
      /^\/([^/]+)\/([^/]+)\/pull\/(\d+)(?:\/|$)/
    );
    if (!match) return null;
    const prNum = parseInt(match[3], 10);
    return {
      owner: match[1],
      repo: `${match[1]}/${match[2]}`,
      prNumber: prNum,
      pr: prNum,
    };
  } catch {
    return null;
  }
}
