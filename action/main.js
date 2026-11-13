#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const { spawn, execFileSync } = require("node:child_process");

const lib = require("./lib.js");

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function startDaemon(binPath, baselineDir) {
  const args = lib.sudoArgv(lib.daemonArgs(binPath, baselineDir));
  const socketPath = lib.getSocketPath();
  const { dir: logDir, logPath, fd: logFd } = lib.createDaemonLogPath();
  lib.saveState("STARTED_LOG_DIR", logDir);

  const sudo = lib.sudoBin();
  const daemonEnv = lib.buildDaemonEnv();
  const child = spawn(sudo, args, {
    detached: true,
    stdio: ["ignore", logFd, logFd],
    env: daemonEnv,
  });
  child.unref();
  fs.closeSync(logFd);

  for (let i = 0; i < 100; i++) {
    try {
      execFileSync(sudo, lib.sudoArgv([binPath, "ping", "--socket", socketPath]), {
        stdio: "ignore",
        env: daemonEnv,
      });
      console.log("seccomp-profiler daemon is ready and tracing containers.");
      return logDir;
    } catch (_) {
      await sleep(100);
    }
  }
  let daemonLogs = "";
  try {
    daemonLogs = fs.readFileSync(logPath, "utf8");
  } catch (_) {}
  try {
    fs.rmSync(logDir, { recursive: true, force: true });
  } catch (_) {}
  throw new Error(
    `Timed out waiting for seccomp-profiler daemon readiness on ${socketPath}.\nDaemon log:\n${daemonLogs}`
  );
}

async function run() {
  const mode = lib.getInput("mode", "start").toLowerCase();
  const { binPath, fromCache } = await lib.ensureBinary();
  if (mode === "start") {
    const baselineDir = lib.prepareBaselineCheckout();
    lib.saveState("STARTED_BIN", binPath);
    lib.saveState("STARTED_BIN_FROM_CACHE", fromCache ? "true" : "false");
    lib.saveState("STARTED_SOCKET", lib.getSocketPath());
    lib.saveState("STARTED_STOPPED_MARKER", lib.getStoppedMarker());
    if (baselineDir) {
      lib.saveState("STARTED_BASELINE_DIR", baselineDir);
    }
    try {
      await startDaemon(binPath, baselineDir);
    } catch (err) {
      lib.cleanupBaselineCheckout(baselineDir);
      throw err;
    }
  } else if (mode === "stop") {
    lib.stopDaemon(binPath);
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
  verifySha256: lib.verifySha256,
  verifyPinnedSha256: lib.verifyPinnedSha256,
  verifyCosignSignature: lib.verifyCosignSignature,
  getInput: lib.getInput,
  resolveBpfObjPath: lib.resolveBpfObjPath,
  buildDaemonEnv: lib.buildDaemonEnv,
  sudoArgv: lib.sudoArgv,
  prepareBaselineCheckout: lib.prepareBaselineCheckout,
  daemonArgs: lib.daemonArgs,
  applyStopOutputs: lib.applyStopOutputs,
  stopDaemon: lib.stopDaemon,
  PINNED_RELEASE_REPO: lib.PINNED_RELEASE_REPO,
  PINNED_RELEASE_VERSION: lib.PINNED_RELEASE_VERSION,
  PINNED_BINARY_SHA256: lib.PINNED_BINARY_SHA256,
  COSIGN_SHA256: lib.COSIGN_SHA256,
  COSIGN_CERT_IDENTITY_REGEXP: lib.COSIGN_CERT_IDENTITY_REGEXP,
  COSIGN_OIDC_ISSUER: lib.COSIGN_OIDC_ISSUER,
};
