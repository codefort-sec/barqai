import fs from "fs";
import path from "path";
import { execSync } from "child_process";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, "..");
const distDir = path.resolve(rootDir, "dist");
const chromeDir = path.resolve(distDir, "chrome");
const firefoxDir = path.resolve(distDir, "firefox");

console.log("⚡ Building CodeFort Guard for Chrome and Firefox...");

// 1. Build using Vite
execSync("npm run build", { cwd: rootDir, stdio: "inherit" });

// Helper to copy directory recursively
function copyDir(src, dest) {
  fs.mkdirSync(dest, { recursive: true });
  const entries = fs.readdirSync(src, { withFileTypes: true });

  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);

    if (entry.name === "chrome" || entry.name === "firefox") {
      continue;
    }

    if (entry.isDirectory()) {
      copyDir(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

// 2. Prepare Chrome build in dist/chrome
console.log("📦 Preparing Chrome package...");
fs.rmSync(chromeDir, { recursive: true, force: true });
copyDir(distDir, chromeDir);
// Ensure manifest.firefox.json is removed from Chrome package
const strayFfManifest = path.join(chromeDir, "manifest.firefox.json");
if (fs.existsSync(strayFfManifest)) {
  fs.unlinkSync(strayFfManifest);
}

// 3. Prepare Firefox build in dist/firefox
console.log("🦊 Preparing Firefox package...");
fs.rmSync(firefoxDir, { recursive: true, force: true });
copyDir(distDir, firefoxDir);

// Overwrite manifest.json with Firefox manifest
const ffManifestSource = path.join(rootDir, "public/manifest.firefox.json");
const ffManifestDest = path.join(firefoxDir, "manifest.json");
fs.copyFileSync(ffManifestSource, ffManifestDest);
const strayFfManifestInFf = path.join(firefoxDir, "manifest.firefox.json");
if (fs.existsSync(strayFfManifestInFf)) {
  fs.unlinkSync(strayFfManifestInFf);
}

// 4. Create ZIP archives
console.log("🗜 Creating release archives...");
const projectRoot = fs.existsSync(path.resolve(rootDir, "../../.git"))
  ? path.resolve(rootDir, "../..")
  : rootDir;
const chromeZip = path.join(projectRoot, "codefort-guard-chrome-v0.2.0.zip");
const firefoxZip = path.join(projectRoot, "codefort-guard-firefox-v0.2.0.zip");
const firefoxXpi = path.join(projectRoot, "codefort-guard-firefox-v0.2.0.xpi");
const legacyZip = path.join(projectRoot, "codefort-guard-v0.2.0.zip");

function createZip(sourceDir, destZip) {
  if (fs.existsSync(destZip)) {
    fs.unlinkSync(destZip);
  }
  try {
    if (process.platform === "win32") {
      execSync(`tar -a -c -f "${destZip}" *`, { cwd: sourceDir, stdio: "pipe" });
      return;
    }
  } catch {
    // Fall through to next method
  }
  try {
    execSync(`zip -r "${destZip}" .`, { cwd: sourceDir, stdio: "pipe" });
  } catch {
    if (process.platform === "win32") {
      execSync(
        `powershell -NoProfile -Command "Compress-Archive -Path '${sourceDir}\\*' -DestinationPath '${destZip}' -Force"`,
        { stdio: "inherit" }
      );
    } else {
      throw new Error(`Failed to create zip archive: ${destZip}`);
    }
  }
}

// Zip Chrome
createZip(chromeDir, chromeZip);
fs.copyFileSync(chromeZip, legacyZip);

// Zip Firefox
createZip(firefoxDir, firefoxZip);
fs.copyFileSync(firefoxZip, firefoxXpi);

console.log("\n✅ Packaged successfully!");
console.log(`- Chrome Extension:  ${chromeZip}`);
console.log(`- Firefox Extension: ${firefoxZip}`);
console.log(`- Firefox XPI:       ${firefoxXpi}`);

