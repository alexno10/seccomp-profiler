#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const { execFileSync } = require("node:child_process");

const SOCKET_PATH = process.env.SECCOMP_PROFILER_SOCKET || "/run/seccomp-profiler/ctl.sock";
const STOPPED_MARKER = process.env.SECCOMP_PROFILER_STOPPED_MARKER || "/run/seccomp-profiler/stopped";
const BIN_PATH = process.env.SECCOMP_PROFILER_BIN || "/usr/local/bin/seccomp-profiler";

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

function runPost() {
  if (fs.existsSync(STOPPED_MARKER)) {
    console.log("seccomp-profiler was already stopped explicitly via mode: stop; skipping post hook.");
    return;
  }
  if (!fs.existsSync(SOCKET_PATH)) {
    console.log("seccomp-profiler control socket not found; skipping post hook.");
    return;
  }
  if (!fs.existsSync(BIN_PATH)) {
    console.log("seccomp-profiler binary not found; skipping post hook.");
    return;
  }

  const rawJson = execFileSync(
    "sudo",
    [BIN_PATH, "stop", "--json", "--socket", SOCKET_PATH, "--stopped-marker", STOPPED_MARKER],
    { encoding: "utf8" }
  );
  const resp = JSON.parse(rawJson.trim());
  setOutput("profiles-dir", resp.profilesDir || ".seccomp-profiler/profiles");
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

if (require.main === module) {
  try {
    runPost();
  } catch (err) {
    console.error(err.message || err);
    process.exit(1);
  }
}
