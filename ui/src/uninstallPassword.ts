// The uninstall password is hashed here, in the browser, so only its hash is ever sent or stored. Matches
// UninstallPassword in src/Compliance.Core/Tamper.cs: pbkdf2-sha256$iterations$salt$hash, base64.

const base64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));

/** Whether the browser can hash here: Web Crypto needs HTTPS or this machine (not plain HTTP to another host). */
export const canHashUninstallPassword = () => !!globalThis.crypto?.subtle;

export async function hashUninstallPassword(
  password: string,
  salt: Uint8Array = crypto.getRandomValues(new Uint8Array(16)),
  iterations = 100_000,
): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations },
    key,
    256,
  );
  return `pbkdf2-sha256$${iterations}$${base64(salt)}$${base64(new Uint8Array(bits))}`;
}
