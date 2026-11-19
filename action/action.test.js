"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const {
  getInput,
  resolveBpfObjPath,
  verifySha256,
  verifyPinnedSha256,
  verifyCosignSignature,
  buildDaemonEnv,
  sudoArgv,
  daemonArgs,
  prepareBaselineCheckout,
  PINNED_RELEASE_REPO,
  PINNED_RELEASE_VERSION,
  PINNED_BINARY_SHA256,
  COSIGN_SHA256,
  COSIGN_CERT_IDENTITY_REGEXP,
  COSIGN_OIDC_ISSUER,
} = require("./main.js");

test("getInput reads hyphenated INPUT_<NAME> env vars set by GitHub Actions runner", () => {
  process.env["INPUT_FAIL-ON"] = "any-new";
  process.env["INPUT_OUTPUT-DIR"] = "custom/profiles";
  try {
    assert.equal(getInput("fail-on", "high-risk"), "any-new");
    assert.equal(getInput("output-dir", ".seccomp-profiler/profiles"), "custom/profiles");
  } finally {
    delete process.env["INPUT_FAIL-ON"];
    delete process.env["INPUT_OUTPUT-DIR"];
  }
});

test("resolveBpfObjPath defaults to action repository bpf/profiler.bpf.o", () => {
  delete process.env.SECCOMP_PROFILER_BPF_OBJ;
  const p = resolveBpfObjPath();
  assert.equal(p, path.resolve(__dirname, "..", "bpf", "profiler.bpf.o"));
});

test("buildDaemonEnv strips RUNNER_TRACKING_ID and all GitHub/secret tokens from sudo daemon environment", () => {
  const env = buildDaemonEnv({
    PATH: "/usr/bin",
    HOME: "/home/runner",
    DOCKER_HOST: "unix:///var/run/docker.sock",
    RUNNER_TRACKING_ID: "github_abc123",
    "INPUT_GITHUB-TOKEN": "ghs_secret1",
    INPUT_GITHUB_TOKEN: "ghs_secret2",
    GITHUB_TOKEN: "ghs_secret3",
    GH_TOKEN: "ghs_secret4",
    ACTIONS_RUNTIME_TOKEN: "eyJ_runtime",
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "eyJ_oidc",
    SUPER_SECRET_KEY: "should_not_leak",
  });
  assert.equal(env.PATH, "/usr/bin");
  assert.equal(env.HOME, "/home/runner");
  assert.equal(env.DOCKER_HOST, "unix:///var/run/docker.sock");
  assert.equal("RUNNER_TRACKING_ID" in env, false);
  assert.equal("INPUT_GITHUB-TOKEN" in env, false);
  assert.equal("INPUT_GITHUB_TOKEN" in env, false);
  assert.equal("GITHUB_TOKEN" in env, false);
  assert.equal("GH_TOKEN" in env, false);
  assert.equal("ACTIONS_RUNTIME_TOKEN" in env, false);
  assert.equal("ACTIONS_ID_TOKEN_REQUEST_TOKEN" in env, false);
  assert.equal("SUPER_SECRET_KEY" in env, false);
});

test("release version, repo, and binary/cosign SHA-256 digests are immutably pinned in code", () => {
  assert.equal(PINNED_RELEASE_REPO, "alexno10/seccomp-profiler");
  assert.equal(PINNED_RELEASE_VERSION, "v1.2.0");
  assert.equal(COSIGN_SHA256.amd64, "8b24b946dd5809c6bd93de08033bcf6bc0ed7d336b7785787c080f574b89249b");
  assert.equal(COSIGN_SHA256.arm64, "3b2e2e3854d0356c45fe6607047526ccd04742d20bd44afb5be91fa2a6e7cb4a");
  assert.equal(PINNED_BINARY_SHA256.amd64, "bab765be0ac7b24b8831e62818f3d4d783e5481aee9527ed54bff052a005d1ce");
  assert.equal(PINNED_BINARY_SHA256.arm64, "5da3813ecb4374acd02cef045098181c24fe4ab5daf49efa85aab79e4ec79bba");
});

test("COSIGN_CERT_IDENTITY_REGEXP is strictly anchored and rejects other workflows, repos, or refs", () => {
  assert.equal(
    COSIGN_CERT_IDENTITY_REGEXP,
    "^https://github\\.com/alexno10/seccomp-profiler/\\.github/workflows/release\\.yml@refs/tags/v[0-9]+\\.[0-9]+\\.[0-9]+$"
  );
  assert.equal(COSIGN_OIDC_ISSUER, "https://token.actions.githubusercontent.com");

  const re = new RegExp(COSIGN_CERT_IDENTITY_REGEXP);
  assert.equal(
    re.test("https://github.com/alexno10/seccomp-profiler/.github/workflows/release.yml@refs/tags/v0.2.0"),
    true
  );
  // Negative cases: different repo, prefix/suffix injection, different workflow, branch ref
  assert.equal(
    re.test("https://github.com/evil/seccomp-profiler/.github/workflows/release.yml@refs/tags/v0.2.0"),
    false
  );
  assert.equal(
    re.test("https://evil.com/https://github.com/alexno10/seccomp-profiler/.github/workflows/release.yml@refs/tags/v0.2.0"),
    false
  );
  assert.equal(
    re.test("https://github.com/alexno10/seccomp-profiler/.github/workflows/ci.yml@refs/tags/v0.2.0"),
    false
  );
  assert.equal(
    re.test("https://github.com/alexno10/seccomp-profiler/.github/workflows/release.yml@refs/heads/main"),
    false
  );
  assert.equal(
    re.test("https://github.com/alexno10/seccomp-profiler/.github/workflows/release.yml@refs/tags/v0.2.0-evil"),
    false
  );
});

test("verifyCosignSignature rejects unanchored identity regex and fails on invalid signature", () => {
  assert.throws(
    () => verifyCosignSignature("cosign", "bin", "sig", "cert", "https://github.com/.*/seccomp-profiler/.*"),
    /must be fully anchored/
  );
});

test("verifySha256 and verifyPinnedSha256 accept matching digest and reject tampered binary", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "seccomp-test-"));
  const binPath = path.join(tmpDir, "seccomp-profiler-linux-amd64");
  const sumsPath = path.join(tmpDir, "checksums.txt");
  fs.writeFileSync(binPath, "fake-elf-payload");
  const digest = crypto.createHash("sha256").update("fake-elf-payload").digest("hex");
  fs.writeFileSync(sumsPath, `${digest}  seccomp-profiler-linux-amd64\n`);

  verifySha256(binPath, sumsPath, "seccomp-profiler-linux-amd64");
  verifyPinnedSha256(binPath, digest, "seccomp-profiler-linux-amd64");

  fs.writeFileSync(binPath, "tampered-payload");
  assert.throws(() => verifySha256(binPath, sumsPath, "seccomp-profiler-linux-amd64"), /SHA-256 mismatch/);
  assert.throws(() => verifyPinnedSha256(binPath, digest, "seccomp-profiler-linux-amd64"), /Pinned SHA-256 mismatch/);
});

test("sudo invocation preserves the daemon env allowlist (env_reset bypass)", () => {
  const argv = sudoArgv(["setsid", "/bin/tool", "daemon"]);
  assert.equal(argv[0], "--preserve-env=PATH,HOME,USER,LOGNAME,LANG,LC_ALL,TMPDIR,DOCKER_HOST,DOCKER_CONFIG,DOCKER_API_VERSION,SECCOMP_PROFILER_BPF_OBJ,SECCOMP_PROFILER_SOCKET,SECCOMP_PROFILER_STOPPED_MARKER,SECCOMP_PROFILER_BIN");
  assert.deepEqual(argv.slice(1), ["setsid", "/bin/tool", "daemon"]);
});

test("daemonArgs passes baseline-ref checkout paths and drift flags", () => {
  process.env["INPUT_COMMITTED-PROFILE"] = "seccomp/{name}.json";
  process.env["INPUT_ALLOW-FILE"] = ".seccomp-profiler/accepted.yml";
  try {
    const args = daemonArgs("/bin/seccomp-profiler", "/tmp/baseline-wt");
    const flag = (name) => {
      const i = args.indexOf(name);
      return i === -1 ? undefined : args[i + 1];
    };
    assert.equal(flag("--committed-profile"), path.resolve("/tmp/baseline-wt", "seccomp/{name}.json"));
    assert.equal(flag("--allow-file"), path.resolve("/tmp/baseline-wt", ".seccomp-profiler/accepted.yml"));
    assert.equal(flag("--working-committed-profile"), path.resolve(process.cwd(), "seccomp/{name}.json"));
    assert.equal(flag("--working-allow-file"), path.resolve(process.cwd(), ".seccomp-profiler/accepted.yml"));
    assert.equal(flag("--compose-project"), "");

    // Without a baseline checkout there is no drift comparison.
    const argsNoBaseline = daemonArgs("/bin/seccomp-profiler", null);
    assert.equal(argsNoBaseline[argsNoBaseline.indexOf("--committed-profile") + 1], "seccomp/{name}.json");
    assert.equal(argsNoBaseline[argsNoBaseline.indexOf("--working-committed-profile") + 1], "");
  } finally {
    delete process.env["INPUT_COMMITTED-PROFILE"];
    delete process.env["INPUT_ALLOW-FILE"];
  }
});

test("prepareBaselineCheckout is a no-op outside pull_request events", () => {
  const prevEvent = process.env.GITHUB_EVENT_NAME;
  const prevBase = process.env.GITHUB_BASE_REF;
  delete process.env.GITHUB_EVENT_NAME;
  delete process.env.GITHUB_BASE_REF;
  try {
    assert.equal(prepareBaselineCheckout(), null);
  } finally {
    if (prevEvent !== undefined) process.env.GITHUB_EVENT_NAME = prevEvent;
    if (prevBase !== undefined) process.env.GITHUB_BASE_REF = prevBase;
  }
});

test("buildDaemonEnv sanitizes untrusted PATH entries and falls back cleanly", () => {
  const env = buildDaemonEnv({
    PATH: ".:/tmp/evil:/home/runner/.local/bin:/usr/local/bin:/usr/bin:/bin",
  });
  assert.equal(env.PATH, "/usr/local/bin:/usr/bin:/bin");

  const fallback = buildDaemonEnv({ PATH: "/tmp/only-untrusted:." });
  assert.equal(fallback.PATH, "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
});

test("daemonArgs omits --bpf-obj unless explicit SECCOMP_PROFILER_BPF_OBJ is configured", () => {
  delete process.env.SECCOMP_PROFILER_BPF_OBJ;
  const args = daemonArgs("/usr/local/bin/seccomp-profiler", null);
  assert.equal(args.includes("--bpf-obj"), false);

  const absCustom = path.resolve(os.tmpdir(), "custom.bpf.o");
  process.env.SECCOMP_PROFILER_BPF_OBJ = absCustom;
  try {
    const argsCustom = daemonArgs("/usr/local/bin/seccomp-profiler", null);
    const idx = argsCustom.indexOf("--bpf-obj");
    assert.notEqual(idx, -1);
    assert.equal(argsCustom[idx + 1], absCustom);
  } finally {
    delete process.env.SECCOMP_PROFILER_BPF_OBJ;
  }
});

test("createDaemonLogPath allocates private mkdtemp dir instead of predictable /tmp log", () => {
  const lib = require("./lib.js");
  assert.equal(typeof lib.createDaemonLogPath, "function");
  const { dir, logPath, fd } = lib.createDaemonLogPath();
  try {
    assert.notEqual(logPath, "/tmp/seccomp-profiler-daemon.log");
    assert.equal(path.dirname(logPath), dir);
    assert.equal(typeof fd, "number");
  } finally {
    fs.closeSync(fd);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("downloadFile rejects non-HTTPS URLs and non-HTTPS redirects", async () => {
  const lib = require("./lib.js");
  const dest = path.join(os.tmpdir(), `seccomp-dl-test-${Date.now()}`);
  await assert.rejects(() => lib.downloadFile("http://example.com/file", dest), /HTTPS/i);
  assert.equal(lib.validateDownloadUrl("https://github.com/alexno10/seccomp-profiler/releases/download/v1.2.0/a").protocol, "https:");
  assert.throws(() => lib.validateDownloadUrl("http://github.com/foo"), /HTTPS/i);
  assert.throws(() => lib.validateDownloadUrl("file:///etc/passwd"), /HTTPS/i);
});

test("validateBaselineRef rejects option injection and resolves pull_request_target and merge_group", () => {
  const lib = require("./lib.js");
  assert.throws(() => lib.validateGitRef("--upload-pack=/tmp/evil"), /invalid.*ref/i);
  assert.throws(() => lib.validateGitRef("main..evil"), /invalid.*ref/i);
  assert.equal(lib.validateGitRef("main"), "main");

  assert.equal(lib.resolveBaselineRef({ GITHUB_EVENT_NAME: "pull_request_target", GITHUB_BASE_REF: "main" }, ""), "main");
  assert.equal(lib.resolveBaselineRef({ GITHUB_EVENT_NAME: "merge_group", GITHUB_BASE_REF: "main" }, ""), "main");
  assert.equal(lib.resolveBaselineRef({ GITHUB_EVENT_NAME: "push", GITHUB_BASE_REF: "main" }, ""), "");
});

test("post hook prefers GITHUB_STATE over poisoned GITHUB_ENV and verifies cached binary SHA-256", () => {
  const post = require("./post.js");
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "seccomp-post-test-"));
  const evilBin = path.join(tmpDir, "evil");
  const cachedBin = path.join(tmpDir, "cached");
  const sock = path.join(tmpDir, "ctl.sock");
  fs.writeFileSync(evilBin, "evil");
  fs.writeFileSync(cachedBin, "tampered-cache");
  fs.writeFileSync(sock, "");

  try {
    const resolved = post.resolvePostConfig(
      {
        STATE_STARTED_BIN: cachedBin,
        STATE_STARTED_BIN_FROM_CACHE: "true",
        STATE_STARTED_SOCKET: sock,
        STATE_STARTED_STOPPED_MARKER: path.join(tmpDir, "stopped"),
        SECCOMP_PROFILER_BIN: evilBin,
        SECCOMP_PROFILER_SOCKET: "/tmp/poisoned.sock",
        SECCOMP_PROFILER_STOPPED_MARKER: "/tmp/poisoned-stopped",
      },
      { CACHE_PATH: cachedBin }
    );
    assert.equal(resolved.binPath, cachedBin);
    assert.equal(resolved.socketPath, sock);
    assert.equal(resolved.requirePinnedVerify, true);

    assert.throws(
      () => post.verifyPostBinary(resolved.binPath, resolved.requirePinnedVerify, "amd64"),
      /Pinned SHA-256 mismatch/
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("installBinaryAtomically creates root cache dir, installs staging file, and renames atomically", () => {
  const lib = require("./lib.js");
  const calls = [];
  const fakeExec = (cmd, args, opts) => {
    calls.push({ cmd, args, env: opts && opts.env });
  };
  lib.installBinaryAtomically("/tmp/dl/bin", "/opt/seccomp-profiler/v1.2.0", "/opt/seccomp-profiler/v1.2.0/seccomp-profiler", fakeExec);
  assert.equal(calls.length, 3);
  assert.deepEqual(calls[0].args.slice(0, 2), ["install", "-d"]);
  assert.equal(calls[1].args[0], "install");
  assert.equal(calls[2].args[0], "mv");
  assert.equal(calls[2].args.includes("-f"), true);
});

test("installBinaryAtomically verifies staged binary digest before atomic mv and removes stage on mismatch", () => {
  const lib = require("./lib.js");
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "seccomp-stage-test-"));
  try {
    const src = path.join(tmpDir, "src");
    fs.writeFileSync(src, "trusted-binary-bytes");
    const wantDigest = crypto.createHash("sha256").update("trusted-binary-bytes").digest("hex");
    const destDir = path.join(tmpDir, "opt", "v1.2.0");
    const destPath = path.join(destDir, "seccomp-profiler");
    const ops = [];

    const mockExec = (cmd, args) => {
      if (args[0] === "install" && args[1] === "-d") {
        ops.push("mkdir");
        fs.mkdirSync(args[args.length - 1], { recursive: true });
      } else if (args[0] === "install") {
        ops.push("stage");
        fs.copyFileSync(args[args.length - 2], args[args.length - 1]);
      } else if (args[0] === "mv") {
        ops.push("mv");
        fs.renameSync(args[args.length - 1 - 1], args[args.length - 1]);
      } else if (args[0] === "rm") {
        ops.push("rm");
        fs.rmSync(args[args.length - 1], { force: true });
      }
    };

    lib.installBinaryAtomically(src, destDir, destPath, mockExec, wantDigest, { skipRootCheck: true });
    assert.deepEqual(ops, ["mkdir", "stage", "mv"]);
    assert.equal(fs.readFileSync(destPath, "utf8"), "trusted-binary-bytes");

    const opsBad = [];
    const wrongDigest = "0".repeat(64);
    assert.throws(
      () =>
        lib.installBinaryAtomically(
          src,
          destDir,
          destPath + ".bad",
          (cmd, args) => {
            if (args[0] === "install" && args[1] !== "-d") {
              opsBad.push("stage");
              fs.copyFileSync(args[args.length - 2], args[args.length - 1]);
            } else if (args[0] === "mv") {
              opsBad.push("mv");
            } else if (args[0] === "rm") {
              opsBad.push("rm");
              fs.rmSync(args[args.length - 1], { force: true });
            }
          },
          wrongDigest,
          { skipRootCheck: true }
        ),
      /Pinned SHA-256 mismatch/
    );
    assert.equal(opsBad.includes("mv"), false);
    assert.equal(opsBad.includes("rm"), true);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("post hook skips when STATE_STARTED_BIN is missing even if GITHUB_ENV has SECCOMP_PROFILER_BIN", () => {
  const post = require("./post.js");
  const res = post.resolvePostConfig({
    SECCOMP_PROFILER_BIN: "/tmp/evil-bin",
    SECCOMP_PROFILER_SOCKET: "/tmp/evil.sock",
    SECCOMP_PROFILER_STOPPED_MARKER: "/tmp/evil-stopped",
  });
  assert.equal(res.skip, true);
});

test("resolveStopConfig uses root session.json and ignores poisoned GITHUB_ENV", () => {
  const lib = require("./lib.js");
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "seccomp-stop-cfg-"));
  const prevEnv = {
    bin: process.env.SECCOMP_PROFILER_BIN,
    sock: process.env.SECCOMP_PROFILER_SOCKET,
    marker: process.env.SECCOMP_PROFILER_STOPPED_MARKER,
  };
  try {
    const binPath = path.join(tmpDir, "seccomp-profiler");
    fs.writeFileSync(binPath, "real-binary-content");
    const binSha = lib.sha256File(binPath);
    const sockPath = path.join(tmpDir, "ctl.sock");
    const markerPath = path.join(tmpDir, "stopped");
    const sessionPath = path.join(tmpDir, "session.json");
    fs.writeFileSync(
      sessionPath,
      JSON.stringify({
        binPath,
        binSha256: binSha,
        socketPath: sockPath,
        stoppedMarker: markerPath,
        baselineDir: "",
      })
    );

    process.env.SECCOMP_PROFILER_BIN = path.join(tmpDir, "poisoned-evil");
    process.env.SECCOMP_PROFILER_SOCKET = path.join(tmpDir, "poisoned.sock");
    process.env.SECCOMP_PROFILER_STOPPED_MARKER = path.join(tmpDir, "poisoned.stopped");

    const cfg = lib.resolveStopConfig({
      sessionPath,
      cachePath: path.join(tmpDir, "missing-cache"),
      skipRootCheck: true,
    });
    assert.equal(cfg.binPath, binPath);
    assert.equal(cfg.socketPath, sockPath);
    assert.equal(cfg.stoppedMarker, markerPath);
    assert.equal(cfg.fromSession, true);

    // Tampered binary must fail verification.
    fs.writeFileSync(binPath, "tampered-after-start");
    assert.throws(
      () =>
        lib.resolveStopConfig({
          sessionPath,
          cachePath: path.join(tmpDir, "missing-cache"),
          skipRootCheck: true,
        }),
      /Pinned SHA-256 mismatch/
    );

    // Without session.json, fallback refuses GITHUB_ENV overrides and checks cachePath against pinned digest.
    fs.rmSync(sessionPath);
    const fakeCache = path.join(tmpDir, "cached");
    fs.writeFileSync(fakeCache, "tampered-cache");
    assert.throws(
      () => lib.resolveStopConfig({ sessionPath, cachePath: fakeCache, arch: "amd64", skipRootCheck: true }),
      /Pinned SHA-256 mismatch/
    );
  } finally {
    if (prevEnv.bin === undefined) delete process.env.SECCOMP_PROFILER_BIN;
    else process.env.SECCOMP_PROFILER_BIN = prevEnv.bin;
    if (prevEnv.sock === undefined) delete process.env.SECCOMP_PROFILER_SOCKET;
    else process.env.SECCOMP_PROFILER_SOCKET = prevEnv.sock;
    if (prevEnv.marker === undefined) delete process.env.SECCOMP_PROFILER_STOPPED_MARKER;
    else process.env.SECCOMP_PROFILER_STOPPED_MARKER = prevEnv.marker;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("daemonArgs enforces baselineDir containment and rejects traversal or external absolute paths", () => {
  process.env["INPUT_ALLOW-FILE"] = "../evil/accepted.yml";
  try {
    assert.throws(() => daemonArgs("/bin/seccomp-profiler", "/run/seccomp-profiler/baseline-deadbeef"), /traversal/i);

    process.env["INPUT_ALLOW-FILE"] = path.resolve(os.tmpdir(), "outside", "accepted.yml");
    assert.throws(
      () => daemonArgs("/bin/seccomp-profiler", "/run/seccomp-profiler/baseline-deadbeef"),
      /out-of-workspace/i
    );

    // Absolute path inside process.cwd() remaps cleanly inside baselineDir.
    process.env["INPUT_ALLOW-FILE"] = path.resolve(process.cwd(), ".seccomp-profiler", "accepted.yml");
    const args = daemonArgs("/bin/seccomp-profiler", "/run/seccomp-profiler/baseline-deadbeef");
    const allowFlag = args[args.indexOf("--allow-file") + 1];
    assert.equal(allowFlag, path.resolve("/run/seccomp-profiler/baseline-deadbeef", ".seccomp-profiler", "accepted.yml"));
  } finally {
    delete process.env["INPUT_ALLOW-FILE"];
  }
});

test("assertRootOwnedFile rejects symlinks, non-root uid, and group/world-writable dirs on POSIX", () => {
  const lib = require("./lib.js");
  const makeStat = ({ uid = 0, mode = 0o100755, isFile = true, isSymlink = false }) => ({
    uid,
    mode,
    isFile: () => isFile && !isSymlink,
    isSymbolicLink: () => isSymlink,
  });

  // Strict root chain passes.
  lib.assertRootOwnedFile("/opt/seccomp-profiler/v1.2.0/seccomp-profiler", "bin", {
    platform: "linux",
    lstatSync: (p) =>
      p.endsWith("seccomp-profiler") && p.includes("v1.2.0/")
        ? makeStat({ uid: 0, mode: 0o100755 })
        : makeStat({ uid: 0, mode: 0o040755, isFile: false }),
  });

  // Group-writable parent directory rejected.
  assert.throws(
    () =>
      lib.assertRootOwnedFile("/opt/seccomp-profiler/v1.2.0/seccomp-profiler", "bin", {
        platform: "linux",
        lstatSync: (p) =>
          p === "/opt/seccomp-profiler"
            ? makeStat({ uid: 0, mode: 0o040775, isFile: false })
            : makeStat({ uid: 0, mode: 0o100755 }),
      }),
    /group\/world-writable/
  );

  // Non-root owner rejected.
  assert.throws(
    () =>
      lib.assertRootOwnedFile("/opt/seccomp-profiler/v1.2.0/seccomp-profiler", "bin", {
        platform: "linux",
        lstatSync: (p) =>
          p.includes("v1.2.0/") ? makeStat({ uid: 1001, mode: 0o100755 }) : makeStat({ uid: 0, mode: 0o040755 }),
      }),
    /owned by root/
  );

  // Symlink parent rejected.
  assert.throws(
    () =>
      lib.assertRootOwnedFile("/opt/seccomp-profiler/v1.2.0/seccomp-profiler", "bin", {
        platform: "linux",
        lstatSync: (p) =>
          p === "/opt" ? makeStat({ uid: 0, mode: 0o120777, isSymlink: true, isFile: false }) : makeStat({ uid: 0, mode: 0o100755 }),
      }),
    /symlink/
  );
});

test("setState and setOutput encode multiline values safely using delimiters", () => {
  const lib = require("./lib.js");
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "seccomp-env-test-"));
  const outFile = path.join(tmpDir, "github_output");
  fs.writeFileSync(outFile, "");
  const prev = process.env.GITHUB_OUTPUT;
  process.env.GITHUB_OUTPUT = outFile;
  try {
    lib.setOutput("profiles-dir", "safe/path");
    lib.setOutput("tricky", "line1\nevil=1");
    const content = fs.readFileSync(outFile, "utf8");
    assert.match(content, /^profiles-dir=safe\/path\n/m);
    assert.match(content, /^tricky<<ghadelim_/m);
  } finally {
    if (prev === undefined) delete process.env.GITHUB_OUTPUT;
    else process.env.GITHUB_OUTPUT = prev;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
