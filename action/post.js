#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const lib = require("./lib.js");

function resolvePostConfig(env = process.env, defaults = {}) {
  if (!env.STATE_STARTED_BIN) {
    return {
      skip: true,
      reason: "no STARTED_BIN recorded in GITHUB_STATE (not the start step)",
      baselineDir: env.STATE_STARTED_BASELINE_DIR || "",
      logDir: env.STATE_STARTED_LOG_DIR || "",
    };
  }
  const cachePath = defaults.CACHE_PATH || lib.BIN_CACHE_PATH;
  const defaultSocket = defaults.SOCKET_PATH || lib.DEFAULT_SOCKET_PATH;
  const defaultMarker = defaults.STOPPED_MARKER || lib.DEFAULT_STOPPED_MARKER;
  const arch = defaults.ARCH || (process.arch === "arm64" ? "arm64" : "amd64");

  const binPath = env.STATE_STARTED_BIN;
  const socketPath = env.STATE_STARTED_SOCKET || defaultSocket;
  const stoppedMarker = env.STATE_STARTED_STOPPED_MARKER || defaultMarker;
  const fromCache = env.STATE_STARTED_BIN_FROM_CACHE === "true" || binPath === cachePath;
  const expectedSha256 = fromCache ? lib.PINNED_BINARY_SHA256[arch] : env.STATE_STARTED_BIN_SHA256 || "";

  return {
    skip: false,
    binPath,
    socketPath,
    stoppedMarker,
    requirePinnedVerify: fromCache || Boolean(expectedSha256),
    expectedSha256,
    baselineDir: env.STATE_STARTED_BASELINE_DIR || "",
    logDir: env.STATE_STARTED_LOG_DIR || "",
  };
}

function verifyPostBinary(
  binPath,
  requirePinnedVerify,
  arch = process.arch === "arm64" ? "arm64" : "amd64",
  opts = {}
) {
  if (!path.isAbsolute(binPath)) {
    throw new Error(`Post binary path must be absolute: ${binPath}`);
  }
  const st = fs.lstatSync(binPath);
  if (st.isSymbolicLink() || !st.isFile()) {
    throw new Error(`Post binary must be a regular non-symlink file: ${binPath}`);
  }
  if (requirePinnedVerify) {
    const digest = opts.expectedSha256 || lib.PINNED_BINARY_SHA256[arch];
    lib.verifyPinnedSha256(binPath, digest, `post ${path.basename(binPath)}`);
  }
  if (opts.checkRootOwnership) {
    lib.assertRootOwnedFile(binPath, `post ${path.basename(binPath)}`, opts);
  }
}

function runPost() {
  const cfg = resolvePostConfig();
  if (cfg.skip) {
    return;
  }
  try {
    if (fs.existsSync(cfg.stoppedMarker)) {
      console.log("seccomp-profiler was already stopped explicitly via mode: stop; skipping post hook.");
      return;
    }
    if (!fs.existsSync(cfg.socketPath)) {
      console.log("seccomp-profiler control socket not found; skipping post hook.");
      return;
    }
    if (!fs.existsSync(cfg.binPath)) {
      console.log("seccomp-profiler binary not found; skipping post hook.");
      return;
    }

    const arch = process.arch === "arm64" ? "arm64" : "amd64";
    verifyPostBinary(cfg.binPath, cfg.requirePinnedVerify, arch, {
      expectedSha256: cfg.expectedSha256,
      checkRootOwnership: true,
    });
    lib.stopDaemon(cfg.binPath, cfg.socketPath, cfg.stoppedMarker);
  } finally {
    lib.cleanupBaselineCheckout(cfg.baselineDir);
    lib.removeRootSessionState();
    if (cfg.logDir) {
      try {
        fs.rmSync(cfg.logDir, { recursive: true, force: true });
      } catch (_) {}
    }
  }
}

if (require.main === module) {
  try {
    runPost();
  } catch (err) {
    console.error(err.message || err);
    process.exit(1);
  }
}

module.exports = {
  resolvePostConfig,
  verifyPostBinary,
  runPost,
};
