import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";
import { decryptKeyVault, encryptKeyVault, KEY_VAULT_MAGIC, KEY_VAULT_VERSION } from "../src/js/keymanager.js";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

test("KeyManager vault round-trips keys with the password", async () => {
  let keys = [{ id: 4, name: "test wallet", result: { masterFingerprint: "deadbeef" }, fields: { seed: "example" } }];
  let ignoredKeys = [{ id: 5, name: "ignored wallet", result: { masterFingerprint: "feedface" }, fields: { seed: "ignored" } }];
  let text = await encryptKeyVault(keys, "correct horse battery staple", ignoredKeys);
  let envelope = JSON.parse(text), opened = await decryptKeyVault(text, "correct horse battery staple");
  assert.equal(envelope.magic, KEY_VAULT_MAGIC);
  assert.equal(envelope.version, KEY_VAULT_VERSION);
  assert.deepEqual(opened.keys, keys);
  assert.deepEqual(opened.ignoredKeys, ignoredKeys);
  assert.notEqual(envelope.ciphertext, "");
});

test("KeyManager rejects a wrong password and tampering", async () => {
  let text = await encryptKeyVault([{ id: 1 }], "secret");
  await assert.rejects(() => decryptKeyVault(text, "wrong"), /password is incorrect|modified/);
  let envelope = JSON.parse(text);
  envelope.ciphertext = envelope.ciphertext.slice(0, -1) + (envelope.ciphertext.endsWith("A") ? "B" : "A");
  await assert.rejects(() => decryptKeyVault(JSON.stringify(envelope), "secret"), /password is incorrect|modified/);
});

test("KeyManager rejects missing passwords", async () => {
  await assert.rejects(() => encryptKeyVault([], ""), /password/);
});

test("Key Station delete archives the key for KeyManager restore", async () => {
  let source = await readFile(new URL("../src/js/app.js", import.meta.url), "utf8");
  let match = source.match(/function hodlDeleteActiveKey\(\) \{([\s\S]*?)\n\}/);
  assert.ok(match, "delete handler should exist");
  assert.match(match[1], /hodlVaultDetachFromStation\(state\)/);
  assert.doesNotMatch(match[1], /hodlVaultIgnoreState\(state\)/);
  assert.doesNotMatch(match[1], /hodlKeys\.splice/);
});

test("Key Station deletion keeps the key in KeyManager instead of Ignored keys", async () => {
  let source = await readFile(new URL("../src/js/app.js", import.meta.url), "utf8");
  let match = source.match(/function hodlVaultDetachFromStation\(state\) \{([\s\S]*?)\n\}/);
  assert.ok(match, "station detach handler should exist");
  assert.match(match[1], /hodlVaultPending\.push\(state\)/);
  assert.doesNotMatch(match[1], /hodlVaultIgnored\.push/);
});

test("restoring an ignored key reuses an existing matching Key Station key", async () => {
  let source = await readFile(new URL("../src/js/app.js", import.meta.url), "utf8");
  let match = source.match(/function hodlVaultRestoreIgnored\(entry\) \{([\s\S]*?)\n\}/);
  assert.ok(match, "ignored-key restore handler should exist");
  assert.match(match[1], /hodlKeys\.find\(/);
  assert.match(match[1], /hodlKeys = hodlKeys\.filter\(/);
});

test("imported vault keys stay out of Key Station until explicitly used", async () => {
  let source = await readFile(new URL("../src/js/app.js", import.meta.url), "utf8");
  let match = source.match(/async function hodlVaultImport\(file\) \{([\s\S]*?)\n\}/);
  assert.ok(match, "vault import handler should exist");
  assert.match(match[1], /hodlVaultPending\.push\(state\)/);
  assert.doesNotMatch(match[1], /hodlKeys\.push\(state\)/);
});
