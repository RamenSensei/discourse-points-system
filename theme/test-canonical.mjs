// Diff check: produce canonical bytes for a known TransferPayload from JS,
// and compare against what the Go server would have produced. Run via node.
//
//   node test-canonical.mjs
//
// Expected stdout: `MATCH` (exit 0) or `MISMATCH:` lines (exit 1)

import { canonicalJsonStruct, fromHex } from "./javascripts/discourse/lib/crypto.js";
import { spawnSync } from "node:child_process";
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const fromBytes = fromHex("9418fc6cc9512fc7cc50626f2e7b487f29d3550d4ca3a079e3cbc934ae2fbc58");

const jsBytes = canonicalJsonStruct([
  ["from",            fromBytes],
  ["to_discourse_id", 42],
  ["amount",          100],
  ["nonce",           7],
  ["meta",            { tip_target_post_id: 1234, tip_target_user_id: 42 }],
]);
const jsStr = new TextDecoder().decode(jsBytes);

const goSrc = `
package main

import (
	"encoding/hex"
	"fmt"
	"github.com/forum-points/ledger/internal/ledger"
)

func main() {
	from, _ := hex.DecodeString("9418fc6cc9512fc7cc50626f2e7b487f29d3550d4ca3a079e3cbc934ae2fbc58")
	p := ledger.TransferPayload{
		From:          from,
		ToDiscourseID: 42,
		Amount:        100,
		Nonce:         7,
		Meta:          map[string]any{"tip_target_post_id": 1234, "tip_target_user_id": 42},
	}
	b, err := ledger.CanonicalJSON(p)
	if err != nil { panic(err) }
	fmt.Print(string(b))
}
`;
// Write the temp Go program INSIDE the sidecar module so we can import internal/ledger.
const sidecarDir = new URL("../ledger/sidecar", import.meta.url).pathname;
const tempDir = join(sidecarDir, "cmd", "_canon_check");
const tempGo = join(tempDir, "main.go");
const { mkdirSync } = await import("node:fs");
mkdirSync(tempDir, { recursive: true });
writeFileSync(tempGo, goSrc);

const goRun = spawnSync("go", ["run", "./cmd/_canon_check"], {
  cwd: sidecarDir,
  env: { ...process.env },
  encoding: "utf-8",
  stdio: ["ignore", "pipe", "pipe"],
});
rmSync(tempDir, { recursive: true, force: true });

if (goRun.status !== 0 || goRun.stdout == null) {
  console.error("go run failed (status=" + goRun.status + "):");
  console.error("  stderr:", goRun.stderr ?? "(none)");
  console.error("  error:", goRun.error?.message ?? "(none)");
  process.exit(2);
}

const goStr = goRun.stdout;
if (jsStr === goStr) {
  console.log("MATCH");
  console.log("bytes:", jsStr);
  process.exit(0);
} else {
  console.error("MISMATCH:");
  console.error("  js: " + jsStr);
  console.error("  go: " + goStr);
  process.exit(1);
}
