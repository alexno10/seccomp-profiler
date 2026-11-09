#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const https = require("node:https");
const { spawn, execFileSync } = require("node:child_process");

const SOCKET_PATH = process.env.SECCOMP_PROFILER_SOCKET || "/run/seccomp-profiler/ctl.sock";
const STOPPED_MARKER = process.env.SECCOMP_PROFILER_STOPPED_MARKER || "/run/seccomp-profiler/stopped";
const DAEMON_LOG_PATH = "/tmp/seccomp-profiler-daemon.log";
const BIN_CACHE_PATH = "/usr/local/bin/seccomp-profiler";

const PINNED_RELEASE_REPO = "alexno10/seccomp-profiler";
const PINNED_RELEASE_VERSION = "v1.0.0";

const COSIGN_VERSION = "v2.4.1";
const COSIGN_SHA256 = Object.freeze({
  amd64: "8b24b946dd5809c6bd93de08033bcf6bc0ed7d336b7785787c080f574b89249b",
  arm64: "3b2e2e3854d0356c45fe6607047526ccd04742d20bd44afb5be91fa2a6e7cb4a",
});

const PINNED_BINARY_SHA256 = Object.freeze({
  amd64: "2a5f9a434e120cc6231aac985d763eaf2e30c2e5ed5920849d0f3f07b380595c",
  arm64: "f28075b5f88bbe5f9b229a43bec6634d6eafc08607aaf9e0a763d4098c4a5eaf",
});

const COSIGN_CERT_IDENTITY_REGEXP =
  "^https://github\\.com/alexno10/seccomp-profiler/\\.github/workflows/release\\.yml@refs/tags/v[0-9]+\\.[0-9]+\\.[0-9]+$";
const COSIGN_OIDC_ISSUER = "https://token.actions.githubusercontent.com";

const DAEMON_ENV_ALLOWLIST = Object.freeze([
  "PATH",
  "HOME",
  "USER",
  "LOGNAME",
  "LANG",
  "LC_ALL",
  "TMPDIR",
  "DOCKER_HOST",
  "DOCKER_CONFIG",
  "DOCKER_API_VERSION",
  "SECCOMP_PROFILER_BPF_OBJ",
  "SECCOMP_PROFILER_SOCKET",
  "SECCOMP_PROFILER_STOPPED_MARKER",
]);

function getInput(name, fallback = "") {
  const upper = name.toUpperCase();
  const hyphenKey = "INPUT_" + upper;
  const underscoreKey = "INPUT_" + upper.replace(/-/g, "_");
  const val = process.env[hyphenKey] !== undefined ? process.env[hyphenKey] : process.env[underscoreKey];
  return val !== undefined && val !== "" ? val.trim() : fallback;
}

function resolveBpfObjPath() {
  if (process.env.SECCOMP_PROFILER_BPF_OBJ) {
    return process.env.SECCOMP_PROFILER_BPF_OBJ;
  }
  return path.resolve(__dirname, "..", "bpf", "profiler.bpf.o");
}

function setOutput(key, value) {
  const outPath = process.env.GITHUB_OUTPUT;
  if (!outPath) return;
  fs.appendFileSync(outPath, `${key}=${value}\n`, "utf8");
}

function appendStepSummary(markdown) {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryPath || !markdown) return;
  fs.appendFileSync(summaryPath, markdown + "\n", "utf8");
}

function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        return resolve(downloadFile(res.headers.location, dest));
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} fetching ${url}`));
      }
      const file = fs.createWriteStream(dest);
      res.pipe(file);
      file.on("finish", () => file.close(resolve));
      file.on("error", reject);
    });
    req.on("error", reject);
  });
}

function verifyPinnedSha256(filePath, expectedHex, label) {
  if (!expectedHex || !/^[0-9a-f]{64}$/i.test(expectedHex)) {
    throw new Error(`Invalid or missing pinned SHA-256 digest for ${label}`);
  }
  const fileBytes = fs.readFileSync(filePath);
  const actualHash = crypto.createHash("sha256").update(fileBytes).digest("hex");
  if (actualHash.toLowerCase() !== expectedHex.toLowerCase()) {
    throw new Error(`Pinned SHA-256 mismatch for ${label}: expected ${expectedHex}, got ${actualHash}`);
  }
}

function verifySha256(filePath, checksumsPath, assetName) {
  const fileBytes = fs.readFileSync(filePath);
  const actualHash = crypto.createHash("sha256").update(fileBytes).digest("hex");
  const lines = fs.readFileSync(checksumsPath, "utf8").split(/\r?\n/);
  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    if (parts.length >= 2 && parts[1].replace(/^\*/, "") === assetName) {
      if (parts[0].toLowerCase() !== actualHash.toLowerCase()) {
        throw new Error(`SHA-256 mismatch for ${assetName}: expected ${parts[0]}, got ${actualHash}`);
      }
      return;
    }
  }
  throw new Error(`Asset ${assetName} not found in checksums.txt`);
}

async function ensureCosign(arch, tmpDir) {
  const cosignUrl = `https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-${arch}`;
  const cosignBin = path.join(tmpDir, "cosign");
  await downloadFile(cosignUrl, cosignBin);
  verifyPinnedSha256(cosignBin, COSIGN_SHA256[arch], `cosign-linux-${arch}`);
  fs.chmodSync(cosignBin, 0o755);
  return cosignBin;
}

function verifyCosignSignature(
  cosignBin,
  filePath,
  sigPath,
  certPath,
  identityRegexp = COSIGN_CERT_IDENTITY_REGEXP,
  oidcIssuer = COSIGN_OIDC_ISSUER
) {
  if (typeof identityRegexp !== "string" || !identityRegexp.startsWith("^") || !identityRegexp.endsWith("$")) {
    throw new Error(`Cosign certificate identity regexp must be fully anchored (^...$): ${identityRegexp}`);
  }
  if (!oidcIssuer) {
    throw new Error("Cosign OIDC issuer must be explicitly specified");
  }
  execFileSync(
    cosignBin,
    [
      "verify-blob",
      "--certificate",
      certPath,
      "--signature",
      sigPath,
      "--certificate-identity-regexp",
      identityRegexp,
      "--certificate-oidc-issuer",
      oidcIssuer,
      filePath,
    ],
    { stdio: "inherit" }
  );
}

async function downloadReleaseAssets(repo, version, assetName, tmpDir) {
  const baseUrl = `https://github.com/${repo}/releases/download/${version}`;
  const binTmp = path.join(tmpDir, assetName);
  const sigTmp = path.join(tmpDir, `${assetName}.sig`);
  const certTmp = path.join(tmpDir, `${assetName}.pem`);
  const sumsTmp = path.join(tmpDir, "checksums.txt");
  const sumsSigTmp = path.join(tmpDir, "checksums.txt.sig");
  const sumsCertTmp = path.join(tmpDir, "checksums.txt.pem");

  await downloadFile(`${baseUrl}/${assetName}`, binTmp);
  await downloadFile(`${baseUrl}/${assetName}.sig`, sigTmp);
  await downloadFile(`${baseUrl}/${assetName}.pem`, certTmp);
  await downloadFile(`${baseUrl}/checksums.txt`, sumsTmp);
  await downloadFile(`${baseUrl}/checksums.txt.sig`, sumsSigTmp);
  await downloadFile(`${baseUrl}/checksums.txt.pem`, sumsCertTmp);

  return { binTmp, sigTmp, certTmp, sumsTmp, sumsSigTmp, sumsCertTmp };
}

async function ensureBinary() {
  if (fs.existsSync(BIN_CACHE_PATH)) {
    return BIN_CACHE_PATH;
  }

  const arch = process.arch === "arm64" ? "arm64" : "amd64";
  const repo = PINNED_RELEASE_REPO;
  const version = PINNED_RELEASE_VERSION;
  const assetName = `seccomp-profiler-linux-${arch}`;
  const tmpDir = fs.mkdtempSync("/tmp/seccomp-profiler-");

  const { binTmp, sigTmp, certTmp, sumsTmp, sumsSigTmp, sumsCertTmp } = await downloadReleaseAssets(
    repo,
    version,
    assetName,
    tmpDir
  );

  const cosignBin = await ensureCosign(arch, tmpDir);

  // 1. Verify Cosign signature on checksums.txt before trusting its contents.
  verifyCosignSignature(cosignBin, sumsTmp, sumsSigTmp, sumsCertTmp);

  // 2. Verify binary digest against signed checksums.txt AND against commit-locked PINNED_BINARY_SHA256.
  verifySha256(binTmp, sumsTmp, assetName);
  verifyPinnedSha256(binTmp, PINNED_BINARY_SHA256[arch], assetName);

  // 3. Verify Cosign signature on the binary itself.
  verifyCosignSignature(cosignBin, binTmp, sigTmp, certTmp);

  fs.chmodSync(binTmp, 0o755);
  execFileSync("sudo", ["cp", binTmp, BIN_CACHE_PATH], { stdio: "inherit" });
  return BIN_CACHE_PATH;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function buildDaemonEnv(baseEnv = process.env) {
  const env = {};
  for (const key of DAEMON_ENV_ALLOWLIST) {
    if (baseEnv[key] !== undefined) {
      env[key] = baseEnv[key];
    }
  }
  return env;
}

async function startDaemon(binPath) {
  const bpfObjPath = resolveBpfObjPath();
  const args = [
    "setsid",
    binPath,
    "daemon",
    "--socket",
    SOCKET_PATH,
    "--stopped-marker",
    STOPPED_MARKER,
    "--bpf-obj",
    bpfObjPath,
    "--targets",
    getInput("targets", ""),
    "--group-by",
    getInput("group-by", "auto"),
    "--exclude-images",
    getInput("exclude-images", ""),
    "--output-dir",
    getInput("output-dir", ".seccomp-profiler/profiles"),
    "--committed-profile",
    getInput("committed-profile", ".seccomp-profiler/profiles/{name}.json"),
    "--baseline",
    getInput("baseline", "standard"),
    "--runtime",
    getInput("runtime", "auto"),
    "--extra-allow",
    getInput("extra-allow", ""),
    "--on-change",
    getInput("on-change", "report"),
    "--fail-on",
    getInput("fail-on", "high-risk"),
    "--allow-file",
    getInput("allow-file", ".seccomp-profiler/accepted.yml"),
  ];

  const logFd = fs.openSync(DAEMON_LOG_PATH, "w");
  const child = spawn("sudo", args, {
    detached: true,
    stdio: ["ignore", logFd, logFd],
    env: buildDaemonEnv(),
  });
  child.unref();
  fs.closeSync(logFd);

  for (let i = 0; i < 100; i++) {
    try {
      execFileSync("sudo", [binPath, "ping", "--socket", SOCKET_PATH], { stdio: "ignore" });
      console.log("seccomp-profiler daemon is ready and tracing containers.");
      return;
    } catch (_) {
      await sleep(100);
    }
  }
  let daemonLogs = "";
  try {
    daemonLogs = fs.readFileSync(DAEMON_LOG_PATH, "utf8");
  } catch (_) {}
  throw new Error(
    `Timed out waiting for seccomp-profiler daemon readiness on ${SOCKET_PATH}.\nDaemon log:\n${daemonLogs}`
  );
}

function stopDaemon(binPath) {
  const rawJson = execFileSync(
    "sudo",
    [binPath, "stop", "--json", "--socket", SOCKET_PATH, "--stopped-marker", STOPPED_MARKER],
    { encoding: "utf8" }
  );
  const resp = JSON.parse(rawJson.trim());
  setOutput("profiles-dir", resp.profilesDir || getInput("output-dir", ".seccomp-profiler/profiles"));
  setOutput("raw-dir", resp.rawDir || ".seccomp-profiler/raw");
  setOutput("new-syscalls-count", String(resp.newSyscallsCount ?? 0));
  setOutput("high-risk-count", String(resp.highRiskCount ?? 0));
  setOutput("gate-passed", String(Boolean(resp.gatePassed)));

  if (resp.markdownSummary) {
    appendStepSummary(resp.markdownSummary);
    console.log(resp.markdownSummary);
  }
  if (!resp.gatePassed) {
    console.error(`Security gate failed: ${resp.gateReason}`);
    process.exit(1);
  }
}

async function run() {
  const mode = getInput("mode", "start").toLowerCase();
  const binPath = await ensureBinary();
  if (mode === "start") {
    await startDaemon(binPath);
  } else if (mode === "stop") {
    stopDaemon(binPath);
  } else {
    throw new Error(`Invalid mode "${mode}": must be "start" or "stop"`);
  }
}

if (require.main === module) {
  run().catch((err) => {
    console.error(err.message || err);
    process.exit(1);
  });
}

module.exports = {
  verifySha256,
  verifyPinnedSha256,
  verifyCosignSignature,
  getInput,
  resolveBpfObjPath,
  buildDaemonEnv,
  stopDaemon,
  PINNED_RELEASE_REPO,
  PINNED_RELEASE_VERSION,
  PINNED_BINARY_SHA256,
  COSIGN_SHA256,
  COSIGN_CERT_IDENTITY_REGEXP,
  COSIGN_OIDC_ISSUER,
};
