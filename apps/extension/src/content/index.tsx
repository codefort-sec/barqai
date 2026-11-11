/**
 * CODEFORT Guard - Content Script Entrypoint
 * Injects security status badges and diff warnings into GitHub Pull Requests.
 */

import "./content.css";
import { GitHubObserver } from "./github-observer";

const observer = new GitHubObserver();
observer.start();
