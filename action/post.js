#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const lib = require("./lib.js");

function runPost() {
  if (fs.existsSync(lib.STOPPED_MARKER)) {
    console.log("seccomp-profiler was already stopped explicitly via mode: stop; skipping post hook.");
    return;
  }
  if (!fs.existsSync(lib.SOCKET_PATH)) {
    console.log("seccomp-profiler control socket not found; skipping post hook.");
    return;
  }
  const binPath = process.env.SECCOMP_PROFILER_BIN || lib.BIN_CACHE_PATH;
  if (!fs.existsSync(binPath)) {
    console.log("seccomp-profiler binary not found; skipping post hook.");
    return;
  }

  lib.stopDaemon(binPath);
}

if (require.main === module) {
  try {
    runPost();
  } catch (err) {
    console.error(err.message || err);
    process.exit(1);
  }
}
