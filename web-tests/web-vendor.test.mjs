import assert from "node:assert/strict";
import test from "node:test";
import { verifyVendor } from "../scripts/verify-web-vendor.mjs";

test("vendored Noble files match the approved immutable manifest", async () => {
  const report = await verifyVendor(new URL("../", import.meta.url));
  assert.deepEqual(report.packages, [
    "@noble/ciphers@2.4.0",
    "@noble/curves@2.4.0",
    "@noble/hashes@2.4.0",
  ]);
  assert.equal(report.filesVerified, 58);
});
