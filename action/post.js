#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const lib = require("./lib.js");

function resolvePostConfig(env = process.env, defaults = {}) {
  const cachePath = defaults.CACHE_PATH || lib.BIN_CACHE_PATH;
  const defaultSocket = defaults.SOCKET_PATH || lib.DEFAULT_SOCKET_PATH;
  const defaultMarker = defaults.STOPPED_MARKER || lib.DEFAULT_STOPPED_MARKER;

  const hasStateBin = Boolean(env.STATE_STARTED_BIN);
  const binPath = env.STATE_STARTED_BIN || env.SECCOMP_PROFILER_BIN || cachePath;
  const socketPath = env.STATE_STARTED_SOCKET || env.SECCOMP_PROFILER_SOCKET || defaultSocket;
  const stoppedMarker = env.STATE_STARTED_STOPPED_MARKER || env.SECCOMP_PROFILER_STOPPED_MARKER || defaultMarker;

  // Require pinned SHA-256 verification whenever we run the cached release binary
  // (or when start recorded cache usage in GITHUB_STATE), even if $GITHUB_ENV was
  // tampered with by an intermediate job step.
  const requirePinnedVerify = hasStateBin
    ? env.STATE_STARTED_BIN_FROM_CACHE === "true" || binPath === cachePath
    : !env.SECCOMP_PROFILER_BIN || binPath === cachePath;

  return {
    binPath,
    socketPath,
    stoppedMarker,
    requirePinnedVerify,
    baselineDir: env.STATE_STARTED_BASELINE_DIR || "",
    logDir: env.STATE_STARTED_LOG_DIR || "",
  };
}

function verifyPostBinary(binPath, requirePinnedVerify, arch = process.arch === "arm64" ? "arm64" : "amd64") {
  if (!path.isAbsolute(binPath)) {
    throw new Error(`Post binary path must be absolute: ${binPath}`);
  }
  const st = fs.lstatSync(binPath);
  if (st.isSymbolicLink() || !st.isFile()) {
    throw new Error(`Post binary must be a regular non-symlink file: ${binPath}`);
  }
  if (requirePinnedVerify) {
    lib.verifyPinnedSha256(binPath, lib.PINNED_BINARY_SHA256[arch], `cached post ${path.basename(binPath)}`);
  }
}

function runPost() {
  const cfg = resolvePostConfig();
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

    verifyPostBinary(cfg.binPath, cfg.requirePinnedVerify);
    lib.stopDaemon(cfg.binPath, cfg.socketPath, cfg.stoppedMarker);
  } finally {
    lib.cleanupBaselineCheckout(cfg.baselineDir);
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
