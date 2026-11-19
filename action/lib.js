"use strict";

// Shared helpers for main.js (start) and post.js (post hook).

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const https = require("node:https");
const { execFileSync } = require("node:child_process");

const DEFAULT_SOCKET_PATH = "/run/seccomp-profiler/ctl.sock";
const DEFAULT_STOPPED_MARKER = "/run/seccomp-profiler/stopped";
const SESSION_STATE_DIR = "/run/seccomp-profiler";
const SESSION_STATE_PATH = `${SESSION_STATE_DIR}/session.json`;
const BASELINE_DIR_PREFIX = `${SESSION_STATE_DIR}/baseline-`;
const SOCKET_PATH = process.env.SECCOMP_PROFILER_SOCKET || DEFAULT_SOCKET_PATH;
const STOPPED_MARKER = process.env.SECCOMP_PROFILER_STOPPED_MARKER || DEFAULT_STOPPED_MARKER;

const PINNED_RELEASE_REPO = "alexno10/seccomp-profiler";
const PINNED_RELEASE_VERSION = "v1.2.0";

// Versioned cache location: a new pinned release automatically uses a new
// cache path, and any file found there is verified against the pinned digest
// before it is executed (never trust a cached binary blindly).
const BIN_CACHE_DIR = `/opt/seccomp-profiler/${PINNED_RELEASE_VERSION}`;
const BIN_CACHE_PATH = `${BIN_CACHE_DIR}/seccomp-profiler`;

const COSIGN_VERSION = "v2.4.1";
const COSIGN_SHA256 = Object.freeze({
  amd64: "8b24b946dd5809c6bd93de08033bcf6bc0ed7d336b7785787c080f574b89249b",
  arm64: "3b2e2e3854d0356c45fe6607047526ccd04742d20bd44afb5be91fa2a6e7cb4a",
});

const PINNED_BINARY_SHA256 = Object.freeze({
  amd64: "bab765be0ac7b24b8831e62818f3d4d783e5481aee9527ed54bff052a005d1ce",
  arm64: "5da3813ecb4374acd02cef045098181c24fe4ab5daf49efa85aab79e4ec79bba",
});

const COSIGN_CERT_IDENTITY_REGEXP =
  "^https://github\\.com/alexno10/seccomp-profiler/\\.github/workflows/release\\.yml@refs/tags/v[0-9]+\\.[0-9]+\\.[0-9]+$";
const COSIGN_OIDC_ISSUER = "https://token.actions.githubusercontent.com";

const SAFE_SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const TRUSTED_PATH_DIR_RE = /^\/(?:usr\/(?:local\/)?(?:sbin|bin)|sbin|bin)$/;

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
  "SECCOMP_PROFILER_BIN",
]);

function sudoBin() {
  return fs.existsSync("/usr/bin/sudo") ? "/usr/bin/sudo" : "sudo";
}

function sanitizePath(rawPath) {
  if (typeof rawPath !== "string" || rawPath.trim() === "") {
    return SAFE_SYSTEM_PATH;
  }
  const kept = rawPath
    .split(":")
    .map((p) => p.trim())
    .filter((p) => TRUSTED_PATH_DIR_RE.test(p));
  return kept.length > 0 ? kept.join(":") : SAFE_SYSTEM_PATH;
}

function getInput(name, fallback = "") {
  const upper = name.toUpperCase();
  const hyphenKey = "INPUT_" + upper;
  const underscoreKey = "INPUT_" + upper.replace(/-/g, "_");
  const val = process.env[hyphenKey] !== undefined ? process.env[hyphenKey] : process.env[underscoreKey];
  return val !== undefined && val !== "" ? val.trim() : fallback;
}

function validateAbsoluteFilePath(p, label) {
  if (!path.isAbsolute(p)) {
    throw new Error(`${label} must be an absolute path: ${p}`);
  }
  return p;
}

function getSocketPath(env = process.env) {
  const raw = env.STATE_STARTED_SOCKET || env.SECCOMP_PROFILER_SOCKET || DEFAULT_SOCKET_PATH;
  return validateAbsoluteFilePath(raw, "SECCOMP_PROFILER_SOCKET");
}

function getStoppedMarker(env = process.env) {
  const raw = env.STATE_STARTED_STOPPED_MARKER || env.SECCOMP_PROFILER_STOPPED_MARKER || DEFAULT_STOPPED_MARKER;
  return validateAbsoluteFilePath(raw, "SECCOMP_PROFILER_STOPPED_MARKER");
}

function resolveBpfObjPath() {
  if (process.env.SECCOMP_PROFILER_BPF_OBJ) {
    return validateAbsoluteFilePath(process.env.SECCOMP_PROFILER_BPF_OBJ, "SECCOMP_PROFILER_BPF_OBJ");
  }
  return path.resolve(__dirname, "..", "bpf", "profiler.bpf.o");
}

function appendCommandFile(filePath, key, value) {
  if (!filePath) return;
  const k = String(key);
  if (/[\r\n=]|<</.test(k)) {
    throw new Error(`Invalid GitHub Actions command-file key: ${k}`);
  }
  const str = String(value ?? "");
  if (str.includes("\n") || str.includes("\r")) {
    const delim = `ghadelim_${crypto.randomBytes(12).toString("hex")}`;
    fs.appendFileSync(filePath, `${k}<<${delim}\n${str}\n${delim}\n`, "utf8");
    return;
  }
  fs.appendFileSync(filePath, `${k}=${str}\n`, "utf8");
}

function setOutput(key, value) {
  appendCommandFile(process.env.GITHUB_OUTPUT, key, value);
}

function saveState(key, value) {
  appendCommandFile(process.env.GITHUB_STATE, key, value);
}

function appendStepSummary(markdown) {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryPath || !markdown) return;
  fs.appendFileSync(summaryPath, markdown + "\n", "utf8");
}

function createDaemonLogPath() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "seccomp-profiler-log-"));
  try {
    fs.chmodSync(dir, 0o700);
  } catch (_) {}
  const logPath = path.join(dir, "daemon.log");
  const fd = fs.openSync(logPath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
  return { dir, logPath, fd };
}

function validateDownloadUrl(rawUrl) {
  const parsed = new URL(rawUrl);
  if (parsed.protocol !== "https:") {
    throw new Error(`Refusing non-HTTPS URL protocol "${parsed.protocol}" for ${parsed.hostname || rawUrl}`);
  }
  return parsed;
}

function downloadFile(url, dest, depth = 0) {
  return new Promise((resolve, reject) => {
    if (depth > 5) {
      return reject(new Error(`Too many redirects fetching ${url}`));
    }
    let parsed;
    try {
      parsed = validateDownloadUrl(url);
    } catch (err) {
      return reject(err);
    }

    const req = https.get(parsed, { timeout: 120000 }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        let next;
        try {
          next = validateDownloadUrl(new URL(res.headers.location, parsed).toString()).toString();
        } catch (err) {
          return reject(err);
        }
        return resolve(downloadFile(next, dest, depth + 1));
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} fetching ${url}`));
      }
      const file = fs.createWriteStream(dest, { mode: 0o600 });
      const fail = (err) => {
        res.destroy();
        file.destroy();
        try {
          fs.rmSync(dest, { force: true });
        } catch (_) {}
        reject(err);
      };
      res.on("error", fail);
      file.on("error", fail);
      file.on("finish", () => file.close(resolve));
      res.pipe(file);
    });
    req.on("timeout", () => req.destroy(new Error(`Timeout fetching ${url}`)));
    req.on("error", reject);
  });
}

function assertRegularFileNotSymlink(filePath, label, lstatFn = fs.lstatSync) {
  const st = lstatFn(filePath);
  if (st.isSymbolicLink() || !st.isFile()) {
    throw new Error(`${label} must be a regular non-symlink file: ${filePath}`);
  }
  return st;
}

function assertRootOwnedFile(filePath, label, opts = {}) {
  const lstatFn = opts.lstatSync || fs.lstatSync;
  const platform = opts.platform || process.platform;
  if (!path.isAbsolute(filePath)) {
    throw new Error(`${label} must be an absolute path: ${filePath}`);
  }
  assertRegularFileNotSymlink(filePath, label, lstatFn);
  if (platform === "win32" || opts.skipRootCheck) {
    return;
  }
  let cur = path.posix.resolve(filePath);
  while (true) {
    const cst = lstatFn(cur);
    if (cst.isSymbolicLink()) {
      throw new Error(`${label} path component must not be a symlink: ${cur}`);
    }
    if (typeof cst.uid === "number" && cst.uid !== 0) {
      throw new Error(`${label} path component must be owned by root (uid=0, got ${cst.uid}): ${cur}`);
    }
    if (typeof cst.mode === "number" && (cst.mode & 0o022) !== 0) {
      throw new Error(
        `${label} path component must not be group/world-writable (${(cst.mode & 0o777).toString(8)}): ${cur}`
      );
    }
    const parent = path.posix.dirname(cur);
    if (parent === cur) {
      break;
    }
    cur = parent;
  }
}

function sha256File(filePath) {
  assertRegularFileNotSymlink(filePath, path.basename(filePath));
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function verifyPinnedSha256(filePath, expectedHex, label) {
  if (!expectedHex || !/^[0-9a-f]{64}$/i.test(expectedHex)) {
    throw new Error(`Invalid or missing pinned SHA-256 digest for ${label}`);
  }
  assertRegularFileNotSymlink(filePath, label);
  const fileBytes = fs.readFileSync(filePath);
  const actualHash = crypto.createHash("sha256").update(fileBytes).digest("hex");
  if (actualHash.toLowerCase() !== expectedHex.toLowerCase()) {
    throw new Error(`Pinned SHA-256 mismatch for ${label}: expected ${expectedHex}, got ${actualHash}`);
  }
}

function verifySha256(filePath, checksumsPath, assetName) {
  assertRegularFileNotSymlink(filePath, assetName);
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

function installBinaryAtomically(
  srcPath,
  destDir,
  destPath,
  execFn = execFileSync,
  expectedSha256 = "",
  verifyOpts = {}
) {
  const sudo = sudoBin();
  const env = buildDaemonEnv();
  execFn(sudo, ["install", "-d", "-o", "root", "-g", "root", "-m", "0755", destDir], { stdio: "inherit", env });
  const stagePath = `${destPath}.tmp.${process.pid}.${crypto.randomBytes(4).toString("hex")}`;
  try {
    execFn(sudo, ["install", "-o", "root", "-g", "root", "-m", "0755", srcPath, stagePath], { stdio: "inherit", env });
    if (expectedSha256) {
      assertRootOwnedFile(stagePath, `staged ${path.basename(destPath)}`, verifyOpts);
      verifyPinnedSha256(stagePath, expectedSha256, `staged ${path.basename(destPath)}`);
    }
    execFn(sudo, ["mv", "-f", stagePath, destPath], { stdio: "inherit", env });
  } catch (err) {
    try {
      execFn(sudo, ["rm", "-f", stagePath], { stdio: "ignore", env });
    } catch (_) {}
    throw err;
  }
}

function writeRootSessionState(session, sessionPath = SESSION_STATE_PATH, execFn = execFileSync) {
  const sudo = sudoBin();
  const env = buildDaemonEnv();
  const dir = path.posix.dirname(sessionPath);
  execFn(sudo, ["install", "-d", "-o", "root", "-g", "root", "-m", "0755", dir], { stdio: "inherit", env });
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "seccomp-session-"));
  const tmpJson = path.join(tmpDir, "session.json");
  const stagePath = `${sessionPath}.tmp.${process.pid}.${crypto.randomBytes(4).toString("hex")}`;
  try {
    fs.writeFileSync(tmpJson, JSON.stringify(session, null, 2) + "\n", { mode: 0o600 });
    execFn(sudo, ["install", "-o", "root", "-g", "root", "-m", "0644", tmpJson, stagePath], {
      stdio: "inherit",
      env,
    });
    execFn(sudo, ["mv", "-f", stagePath, sessionPath], { stdio: "inherit", env });
  } catch (err) {
    try {
      execFn(sudo, ["rm", "-f", stagePath], { stdio: "ignore", env });
    } catch (_) {}
    throw err;
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function readRootSessionState(sessionPath = SESSION_STATE_PATH, opts = {}) {
  assertRootOwnedFile(sessionPath, "seccomp-profiler session state", opts);
  const raw = (opts.readFileSync || fs.readFileSync)(sessionPath, "utf8");
  const session = JSON.parse(raw);
  if (!session || typeof session !== "object") {
    throw new Error(`Invalid session state JSON in ${sessionPath}`);
  }
  validateAbsoluteFilePath(session.binPath, "session.binPath");
  if (!session.binSha256 || !/^[0-9a-f]{64}$/i.test(session.binSha256)) {
    throw new Error(`Missing or invalid session.binSha256 in ${sessionPath}`);
  }
  validateAbsoluteFilePath(session.socketPath, "session.socketPath");
  validateAbsoluteFilePath(session.stoppedMarker, "session.stoppedMarker");
  if (session.baselineDir) {
    validateAbsoluteFilePath(session.baselineDir, "session.baselineDir");
  }
  return session;
}

function removeRootSessionState(sessionPath = SESSION_STATE_PATH, execFn = execFileSync) {
  try {
    execFn(sudoBin(), ["rm", "-f", "--", sessionPath], { stdio: "ignore", env: buildDaemonEnv() });
  } catch (_) {}
}

function resolveStopConfig(opts = {}) {
  const sessionPath = opts.sessionPath || SESSION_STATE_PATH;
  const cachePath = opts.cachePath || BIN_CACHE_PATH;
  const arch = opts.arch || (process.arch === "arm64" ? "arm64" : "amd64");
  const existsFn = opts.existsSync || fs.existsSync;

  if (existsFn(sessionPath)) {
    const session = readRootSessionState(sessionPath, opts);
    assertRootOwnedFile(session.binPath, "started seccomp-profiler binary", opts);
    verifyPinnedSha256(session.binPath, session.binSha256, "started seccomp-profiler binary");
    return {
      binPath: session.binPath,
      socketPath: session.socketPath,
      stoppedMarker: session.stoppedMarker,
      baselineDir: session.baselineDir || "",
      fromSession: true,
    };
  }

  // Fallback without session.json (e.g. standalone mode: stop): never trust
  // $GITHUB_ENV's SECCOMP_PROFILER_BIN/SOCKET/STOPPED_MARKER; require root-owned
  // pinned cache binary verified against the hardcoded release digest.
  assertRootOwnedFile(cachePath, "cached seccomp-profiler binary", opts);
  verifyPinnedSha256(cachePath, PINNED_BINARY_SHA256[arch], `cached seccomp-profiler-linux-${arch}`);
  return {
    binPath: cachePath,
    socketPath: DEFAULT_SOCKET_PATH,
    stoppedMarker: DEFAULT_STOPPED_MARKER,
    baselineDir: "",
    fromSession: false,
  };
}

async function ensureBinary() {
  // Explicit override (repo CI testing a fresh build, local development):
  // require root ownership and regular non-symlink file.
  if (process.env.SECCOMP_PROFILER_BIN) {
    const binPath = validateAbsoluteFilePath(process.env.SECCOMP_PROFILER_BIN, "SECCOMP_PROFILER_BIN");
    assertRootOwnedFile(binPath, "SECCOMP_PROFILER_BIN");
    return { binPath, fromCache: false };
  }

  const arch = process.arch === "arm64" ? "arm64" : "amd64";
  const assetName = `seccomp-profiler-linux-${arch}`;

  if (fs.existsSync(BIN_CACHE_PATH)) {
    // A cached binary is only trusted after root-ownership + pinned SHA-256
    // verification (shared runners can be poisoned between jobs).
    try {
      assertRootOwnedFile(BIN_CACHE_PATH, `cached ${assetName}`);
      verifyPinnedSha256(BIN_CACHE_PATH, PINNED_BINARY_SHA256[arch], `cached ${assetName}`);
      return { binPath: BIN_CACHE_PATH, fromCache: true };
    } catch (err) {
      console.log(`Cached binary failed verification (${err.message}); re-downloading.`);
    }
  }

  const repo = PINNED_RELEASE_REPO;
  const version = PINNED_RELEASE_VERSION;
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "seccomp-profiler-"));

  try {
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
    installBinaryAtomically(binTmp, BIN_CACHE_DIR, BIN_CACHE_PATH, execFileSync, PINNED_BINARY_SHA256[arch]);
    return { binPath: BIN_CACHE_PATH, fromCache: true };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function buildDaemonEnv(baseEnv = process.env) {
  const env = {};
  for (const key of DAEMON_ENV_ALLOWLIST) {
    if (baseEnv[key] !== undefined) {
      env[key] = key === "PATH" ? sanitizePath(baseEnv[key]) : baseEnv[key];
    }
  }
  if (env.PATH === undefined) {
    env.PATH = SAFE_SYSTEM_PATH;
  }
  return env;
}

// sudo resets the environment (env_reset/secure_path), so the allowlist must
// be passed explicitly via --preserve-env or DOCKER_HOST & friends never reach
// the root daemon (DinD, rootless Docker, docker context).
function sudoArgv(argv) {
  return ["--preserve-env=" + DAEMON_ENV_ALLOWLIST.join(",")].concat(argv);
}

function validateGitRef(ref) {
  if (typeof ref !== "string" || ref.length === 0 || ref.startsWith("-")) {
    throw new Error(`Invalid baseline git ref: ${ref}`);
  }
  if (/[\s\x00-\x1f\x7f~^:?*\[\\]/.test(ref) || ref.includes("..") || ref.includes("@{")) {
    throw new Error(`Invalid baseline git ref: ${ref}`);
  }
  return ref;
}

function resolveBaselineRef(env = process.env, explicit = getInput("baseline-ref", "")) {
  const eventName = env.GITHUB_EVENT_NAME || "";
  const baseRef = env.GITHUB_BASE_REF || "";
  if (explicit && explicit.toLowerCase() !== "none") {
    return validateGitRef(explicit);
  }
  if ((eventName === "pull_request" || eventName === "pull_request_target" || eventName === "merge_group") && baseRef) {
    return validateGitRef(baseRef);
  }
  return "";
}

// Review item 1: read the committed profile and approvals from a root-owned
// 0700 snapshot of the pristine PR base ref so neither working-tree edits nor
// runner-owned test code during the job can widen the baseline or self-approve.
function prepareBaselineCheckout() {
  const ref = resolveBaselineRef();
  if (!ref) {
    return null;
  }
  console.log(`Fetching pristine baseline from origin/${ref} (committed profile & approvals are read from the base ref).`);
  const gitHardening = [
    "-c",
    "core.symlinks=false",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "submodule.recurse=false",
  ];
  execFileSync("git", gitHardening.concat(["fetch", "--depth=1", "--quiet", "--", "origin", ref]), {
    stdio: ["ignore", "ignore", "inherit"],
  });
  const sha = execFileSync("git", ["rev-parse", "FETCH_HEAD"], { encoding: "utf8" }).trim();
  const wtDir = fs.mkdtempSync(path.join(os.tmpdir(), "seccomp-profiler-wt-"));
  const rootBaselineDir = `${BASELINE_DIR_PREFIX}${crypto.randomBytes(8).toString("hex")}`;
  const sudo = sudoBin();
  const env = buildDaemonEnv();
  try {
    execFileSync("git", gitHardening.concat(["worktree", "add", "--detach", "--quiet", "--", wtDir, sha]), {
      stdio: ["ignore", "ignore", "inherit"],
    });
    execFileSync(sudo, ["install", "-d", "-o", "root", "-g", "root", "-m", "0755", SESSION_STATE_DIR], {
      stdio: "inherit",
      env,
    });
    execFileSync(sudo, ["install", "-d", "-o", "root", "-g", "root", "-m", "0700", rootBaselineDir], {
      stdio: "inherit",
      env,
    });
    execFileSync(sudo, ["cp", "-a", `${wtDir}/.`, rootBaselineDir], { stdio: "inherit", env });
    execFileSync(sudo, ["chown", "-R", "root:root", rootBaselineDir], { stdio: "inherit", env });
    execFileSync(sudo, ["chmod", "-R", "go-rwx", rootBaselineDir], { stdio: "inherit", env });
    return rootBaselineDir;
  } catch (err) {
    cleanupBaselineCheckout(rootBaselineDir);
    throw err;
  } finally {
    try {
      execFileSync("git", ["worktree", "remove", "--force", "--", wtDir], { stdio: "ignore" });
    } catch (_) {}
    try {
      fs.rmSync(wtDir, { recursive: true, force: true });
    } catch (_) {}
  }
}

function cleanupBaselineCheckout(dir) {
  if (!dir) return;
  if (new RegExp(`^${SESSION_STATE_DIR.replace(/\//g, "\\/")}/baseline-[0-9a-f]+$`).test(dir)) {
    try {
      execFileSync(sudoBin(), ["rm", "-rf", "--", dir], { stdio: "ignore", env: buildDaemonEnv() });
    } catch (_) {}
    return;
  }
  try {
    execFileSync("git", ["worktree", "remove", "--force", "--", dir], { stdio: "ignore" });
  } catch (_) {}
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (_) {}
}

function resolveInBaseline(inputPath, baselineDir, workspaceDir = process.cwd()) {
  const raw = String(inputPath || "").trim();
  if (!raw) {
    throw new Error("Baseline path must not be empty");
  }
  let rel = raw;
  if (path.isAbsolute(raw)) {
    const absWorkspace = path.resolve(workspaceDir);
    const absTarget = path.resolve(raw);
    const computed = path.relative(absWorkspace, absTarget);
    if (computed.startsWith("..") || path.isAbsolute(computed)) {
      throw new Error(`Refusing out-of-workspace absolute path when baseline-ref is active: ${inputPath}`);
    }
    rel = computed || ".";
  }
  const baseRoot = path.resolve(baselineDir);
  const resolved = path.resolve(baseRoot, rel);
  const back = path.relative(baseRoot, resolved);
  if (back.startsWith("..") || path.isAbsolute(back)) {
    throw new Error(`Refusing baseline path traversal outside ${baselineDir}: ${inputPath}`);
  }
  return resolved;
}

function daemonArgs(binPath, baselineDir) {
  const committedInput = getInput("committed-profile", ".seccomp-profiler/profiles/{name}.json");
  const allowInput = getInput("allow-file", ".seccomp-profiler/accepted.yml");

  let committedArg = committedInput;
  let allowArg = allowInput;
  let workingCommitted = "";
  let workingAllow = "";

  if (baselineDir) {
    committedArg = resolveInBaseline(committedInput, baselineDir);
    allowArg = resolveInBaseline(allowInput, baselineDir);
    // Drift detection: flag committed profile / approvals files that the PR
    // itself modified (reported in the summary, review required).
    workingCommitted = path.isAbsolute(committedInput) ? committedInput : path.resolve(process.cwd(), committedInput);
    workingAllow = path.isAbsolute(allowInput) ? allowInput : path.resolve(process.cwd(), allowInput);
  }

  const args = [
    "setsid",
    binPath,
    "daemon",
    "--socket",
    getSocketPath(),
    "--stopped-marker",
    getStoppedMarker(),
  ];

  // Omit --bpf-obj by default so the binary loads its embedded release-signed
  // eBPF object instead of ambient workspace files. Only pass when explicitly set.
  if (process.env.SECCOMP_PROFILER_BPF_OBJ) {
    args.push("--bpf-obj", validateAbsoluteFilePath(process.env.SECCOMP_PROFILER_BPF_OBJ, "SECCOMP_PROFILER_BPF_OBJ"));
  }

  return args
    .concat([
      "--targets",
      getInput("targets", ""),
      "--group-by",
      getInput("group-by", "auto"),
      "--exclude-images",
      getInput("exclude-images", ""),
      "--output-dir",
      getInput("output-dir", ".seccomp-profiler/profiles"),
      "--committed-profile",
      committedArg,
      "--working-committed-profile",
      workingCommitted,
      "--working-allow-file",
      workingAllow,
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
      allowArg,
      "--compose-project",
      getInput("compose-project", ""),
    ])
    .concat(getInput("include-preexisting", "false").toLowerCase() === "true" ? ["--include-preexisting"] : [])
    .concat(getInput("prune", "false").toLowerCase() === "true" ? ["--prune"] : []);
}

function applyStopOutputs(resp, fallbackProfilesDir, fallbackRawDir) {
  setOutput("profiles-dir", resp.profilesDir || fallbackProfilesDir);
  setOutput("raw-dir", resp.rawDir || fallbackRawDir);
  setOutput("new-syscalls-count", String(resp.newSyscallsCount ?? 0));
  setOutput("high-risk-count", String(resp.highRiskCount ?? 0));
  setOutput("gate-passed", String(Boolean(resp.gatePassed)));

  if (resp.markdownSummary) {
    appendStepSummary(resp.markdownSummary);
    console.log(resp.markdownSummary);
  }
}

function stopDaemon(binPath, socketPath = getSocketPath(), stoppedMarker = getStoppedMarker()) {
  const rawJson = execFileSync(
    sudoBin(),
    sudoArgv([binPath, "stop", "--json", "--socket", socketPath, "--stopped-marker", stoppedMarker]),
    { encoding: "utf8", env: buildDaemonEnv(), maxBuffer: 16 * 1024 * 1024 }
  );
  const resp = JSON.parse(rawJson.trim());
  applyStopOutputs(resp, getInput("output-dir", ".seccomp-profiler/profiles"), ".seccomp-profiler/raw");

  if (!resp.gatePassed) {
    throw new Error(`Security gate failed: ${resp.gateReason}`);
  }
}

module.exports = {
  DEFAULT_SOCKET_PATH,
  DEFAULT_STOPPED_MARKER,
  SESSION_STATE_DIR,
  SESSION_STATE_PATH,
  BASELINE_DIR_PREFIX,
  SOCKET_PATH,
  STOPPED_MARKER,
  BIN_CACHE_DIR,
  BIN_CACHE_PATH,
  SAFE_SYSTEM_PATH,
  sudoBin,
  sanitizePath,
  getSocketPath,
  getStoppedMarker,
  setOutput,
  saveState,
  createDaemonLogPath,
  validateDownloadUrl,
  downloadFile,
  assertRootOwnedFile,
  sha256File,
  verifySha256,
  verifyPinnedSha256,
  verifyCosignSignature,
  installBinaryAtomically,
  writeRootSessionState,
  readRootSessionState,
  removeRootSessionState,
  resolveStopConfig,
  resolveInBaseline,
  getInput,
  resolveBpfObjPath,
  buildDaemonEnv,
  sudoArgv,
  validateGitRef,
  resolveBaselineRef,
  prepareBaselineCheckout,
  cleanupBaselineCheckout,
  daemonArgs,
  ensureBinary,
  applyStopOutputs,
  stopDaemon,
  PINNED_RELEASE_REPO,
  PINNED_RELEASE_VERSION,
  PINNED_BINARY_SHA256,
  COSIGN_SHA256,
  COSIGN_CERT_IDENTITY_REGEXP,
  COSIGN_OIDC_ISSUER,
};
