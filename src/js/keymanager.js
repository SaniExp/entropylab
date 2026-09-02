// Encrypted KeyManager vault. This module has no app/UI dependencies so its
// file format and crypto tests can remain stable while the UI evolves.
const MAGIC = "entropylab-keymanager";
const VERSION = 1;
const KDF_ITERATIONS = 600000;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function cryptoApi() {
  if (!globalThis.crypto?.subtle || !globalThis.crypto?.getRandomValues) throw new Error("This browser does not support encrypted key files.");
  return globalThis.crypto;
}

function bytesToBase64(bytes) {
  let text = "";
  for (let i = 0; i < bytes.length; i += 0x8000) text += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(text);
}

function base64ToBytes(value) {
  let text = atob(String(value));
  let bytes = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) bytes[i] = text.charCodeAt(i);
  return bytes;
}

function passwordBytes(password) {
  if (typeof password !== "string" || !password) throw new Error("Enter a password for the key file.");
  return textEncoder.encode(password);
}

async function deriveKey(password, salt) {
  let api = cryptoApi();
  let material = await api.subtle.importKey("raw", passwordBytes(password), { name: "PBKDF2" }, false, ["deriveKey"]);
  return api.subtle.deriveKey({ name: "PBKDF2", salt, iterations: KDF_ITERATIONS, hash: "SHA-512" }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

async function encryptWithKey(payload, key, salt, nonce) {
  let api = cryptoApi();
  let ciphertext = await api.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, textEncoder.encode(JSON.stringify(payload)));
  return JSON.stringify({ magic: MAGIC, version: VERSION, kdf: { name: "PBKDF2-HMAC-SHA512", iterations: KDF_ITERATIONS, salt: bytesToBase64(salt) }, cipher: { name: "AES-256-GCM", nonce: bytesToBase64(nonce) }, ciphertext: bytesToBase64(new Uint8Array(ciphertext)) }, null, 2);
}

export async function encryptKeyVault(keys, password, ignoredKeys = []) {
  let api = cryptoApi(), salt = api.getRandomValues(new Uint8Array(16)), nonce = api.getRandomValues(new Uint8Array(12)), key = await deriveKey(password, salt);
  return encryptWithKey({ format: MAGIC, version: VERSION, keys, ignoredKeys }, key, salt, nonce);
}

export async function decryptKeyVault(text, password) {
  let envelope;
  try { envelope = JSON.parse(String(text)); } catch { throw new Error("The key file is not valid JSON."); }
  if (envelope?.magic !== MAGIC || envelope?.version !== VERSION || envelope?.kdf?.name !== "PBKDF2-HMAC-SHA512" || envelope?.cipher?.name !== "AES-256-GCM") throw new Error("Unsupported or invalid EntropyLab key file.");
  if (envelope.kdf.iterations !== KDF_ITERATIONS) throw new Error("Unsupported key-file KDF parameters.");
  let salt = base64ToBytes(envelope.kdf.salt), nonce = base64ToBytes(envelope.cipher.nonce), key = await deriveKey(password, salt);
  let plaintext;
  try { plaintext = await cryptoApi().subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, base64ToBytes(envelope.ciphertext)); } catch { throw new Error("The password is incorrect or the key file was modified."); }
  let payload;
  try { payload = JSON.parse(textDecoder.decode(plaintext)); } catch { throw new Error("The decrypted key file is invalid."); }
  if (payload?.format !== MAGIC || payload?.version !== VERSION || !Array.isArray(payload.keys)) throw new Error("The decrypted key file has an invalid payload.");
  return { keys: payload.keys, ignoredKeys: Array.isArray(payload.ignoredKeys) ? payload.ignoredKeys : [], key };
}

export async function encryptKeyVaultWithKey(keys, key) {
  let api = cryptoApi(), salt = api.getRandomValues(new Uint8Array(16)), nonce = api.getRandomValues(new Uint8Array(12));
  return encryptWithKey({ format: MAGIC, version: VERSION, keys }, key, salt, nonce);
}

export function keyVaultIdentity(state) {
  return String(state?.result?.masterFingerprint || state?.result?.rootXpub || state?.result?.xpub || state?.id || "");
}

export { MAGIC as KEY_VAULT_MAGIC, VERSION as KEY_VAULT_VERSION, KDF_ITERATIONS as KEY_VAULT_KDF_ITERATIONS };
