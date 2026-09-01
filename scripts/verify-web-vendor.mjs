import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";

const VENDOR_PREFIX = "node_modules/@noble/";
const APPROVED_PACKAGES = {
  "@noble/ciphers": {
    version: "2.4.0",
    tarball: "https://registry.npmjs.org/@noble/ciphers/-/ciphers-2.4.0.tgz",
    integrity: "sha512-AnjFn0Jv92laAkvMrghlFZq4qQCIN/4DxFV/eooqtC2YTjB7kBeLMS2T9KJX4Dn+ZVXLOwK0lSgqDtx9gvxtiw==",
    tarballSha256: "4a398bcc280c8742d474f9162f6d3c153e52ab1078e8ab592b4720410fb3c3e9",
    license: "MIT",
  },
  "@noble/curves": {
    version: "2.4.0",
    tarball: "https://registry.npmjs.org/@noble/curves/-/curves-2.4.0.tgz",
    integrity: "sha512-P4/62zrgfH33CneE3Dn4WhJVA22YUU0eR51wKIan4NVRvwsA0YnPTwWGpNbpuacSujmSFLvyzpyuR30+fbq2Ew==",
    tarballSha256: "55279c71b0201d6c0e58d0206d15825359e02a3932f326ba7b7909ac2d334aa9",
    license: "MIT",
  },
  "@noble/hashes": {
    version: "2.4.0",
    tarball: "https://registry.npmjs.org/@noble/hashes/-/hashes-2.4.0.tgz",
    integrity: "sha512-X5XaVWZIBCT7HHZGm5I7ZQXDwLG+bGXuSrMQAW+7Zvl87h1kmc1ZB1VSRJcpUfoUrGQp4Fkoxm5kZ+Ms+aW+eA==",
    tarballSha256: "e1946149b780017b2564fcc092cb01c04e1d7f20627d0296c17da8868f4436dc",
    license: "MIT",
  },
};

const APPROVED_FILES = {
  ciphers: ["package.json", "LICENSE", "_arx.js", "_poly1305.js", "_polyval.js", "aes.js", "chacha.js", "ff1.js", "index.js", "salsa.js", "utils.js", "webcrypto.js"],
  curves: ["package.json", "LICENSE", "bls12-381.js", "bn254.js", "ed25519.js", "ed448.js", "index.js", "misc.js", "nist.js", "secp256k1.js", "utils.js", "webcrypto.js", "abstract/bls.js", "abstract/curve.js", "abstract/der.js", "abstract/edwards.js", "abstract/fft.js", "abstract/frost.js", "abstract/hash-to-curve.js", "abstract/modular.js", "abstract/montgomery.js", "abstract/oprf.js", "abstract/poseidon.js", "abstract/tower.js", "abstract/weierstrass.js"],
  hashes: ["package.json", "LICENSE", "_blake.js", "_md.js", "_u64.js", "argon2.js", "blake1.js", "blake2.js", "blake3.js", "eskdf.js", "hkdf.js", "hmac.js", "index.js", "legacy.js", "pbkdf2.js", "scrypt.js", "sha2.js", "sha3-addons.js", "sha3.js", "utils.js", "webcrypto.js"],
};

const APPROVED_PATHS = new Set(
  Object.entries(APPROVED_FILES).flatMap(([packageName, files]) =>
    files.map((file) => `${VENDOR_PREFIX}${packageName}/${file}`),
  ),
);

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertManifestShape(manifest) {
  if (!isObject(manifest) || manifest.schemaVersion !== 1 || !Array.isArray(manifest.packages) || !Array.isArray(manifest.files)) {
    throw new Error("invalid vendor manifest shape");
  }
  if (manifest.packages.length !== Object.keys(APPROVED_PACKAGES).length) {
    throw new Error("unexpected approved package count");
  }

  const packageNames = new Set();
  for (const packageEntry of manifest.packages) {
    if (!isObject(packageEntry) || typeof packageEntry.name !== "string" || packageNames.has(packageEntry.name)) {
      throw new Error("invalid or duplicate vendor package");
    }
    packageNames.add(packageEntry.name);
    const approved = APPROVED_PACKAGES[packageEntry.name];
    if (!approved) throw new Error(`unapproved vendor package: ${packageEntry.name}`);
    for (const [field, expected] of Object.entries(approved)) {
      if (packageEntry[field] !== expected) throw new Error(`vendor package ${field} mismatch: ${packageEntry.name}`);
    }
  }
  for (const packageName of Object.keys(APPROVED_PACKAGES)) {
    if (!packageNames.has(packageName)) throw new Error(`missing approved vendor package: ${packageName}`);
  }

  if (manifest.files.length !== APPROVED_PATHS.size) throw new Error("unexpected approved vendor file count");
  const paths = new Set();
  for (const fileEntry of manifest.files) {
    if (!isObject(fileEntry) || typeof fileEntry.path !== "string" || !/^[a-f0-9]{64}$/.test(fileEntry.sha256)) {
      throw new Error("invalid vendor file entry");
    }
    if (fileEntry.path.includes("\\") || path.posix.isAbsolute(fileEntry.path) || fileEntry.path.split("/").some((part) => part === "." || part === ".." || part === "")) {
      throw new Error(`unsafe vendor path: ${fileEntry.path}`);
    }
    if (paths.has(fileEntry.path)) throw new Error(`duplicate vendor path: ${fileEntry.path}`);
    if (!APPROVED_PATHS.has(fileEntry.path)) throw new Error(`unapproved vendor file: ${fileEntry.path}`);
    paths.add(fileEntry.path);
  }
  for (const expectedPath of APPROVED_PATHS) {
    if (!paths.has(expectedPath)) throw new Error(`missing approved vendor file: ${expectedPath}`);
  }
}

async function assertPackageMetadata(webRoot, packageEntry) {
  const packageDirectory = packageEntry.name.slice("@noble/".length);
  const packageJson = JSON.parse(await readFile(new URL(`${VENDOR_PREFIX}${packageDirectory}/package.json`, webRoot), "utf8"));
  if (packageJson.name !== packageEntry.name || packageJson.version !== packageEntry.version) {
    throw new Error(`vendor package version mismatch: ${packageEntry.name}`);
  }
  if (packageJson.license !== packageEntry.license) {
    throw new Error(`vendor package license mismatch: ${packageEntry.name}`);
  }
}

async function rejectUnlistedVendorFiles(webRoot, manifestFiles) {
  const listedPaths = new Set(manifestFiles.map(({ path: filePath }) => filePath));
  const vendorRoot = new URL(VENDOR_PREFIX, webRoot);

  async function walk(directoryUrl, relativeDirectory) {
    for (const entry of await readdir(directoryUrl, { withFileTypes: true })) {
      const relativePath = relativeDirectory ? `${relativeDirectory}/${entry.name}` : entry.name;
      const entryUrl = new URL(`${encodeURIComponent(entry.name)}${entry.isDirectory() ? "/" : ""}`, directoryUrl);
      if (entry.isDirectory()) {
        await walk(entryUrl, relativePath);
      } else if (!entry.isFile()) {
        throw new Error(`non-file vendor entry: ${VENDOR_PREFIX}${relativePath}`);
      } else if (!listedPaths.has(`${VENDOR_PREFIX}${relativePath}`)) {
        throw new Error(`unlisted vendor file: ${VENDOR_PREFIX}${relativePath}`);
      }
    }
  }

  await walk(vendorRoot, "");
}

export async function verifyVendor(projectRootUrl) {
  const webRoot = new URL("app/src/main/assets/web/", projectRootUrl);
  const manifest = JSON.parse(await readFile(new URL("vendor-manifest.json", webRoot), "utf8"));
  assertManifestShape(manifest);
  for (const entry of manifest.files) {
    const bytes = await readFile(new URL(entry.path, webRoot));
    const actual = createHash("sha256").update(bytes).digest("hex");
    if (actual !== entry.sha256) throw new Error(`vendor digest mismatch: ${entry.path}`);
  }
  for (const packageEntry of manifest.packages) await assertPackageMetadata(webRoot, packageEntry);
  await rejectUnlistedVendorFiles(webRoot, manifest.files);
  return {
    packages: manifest.packages.map(({ name, version }) => `${name}@${version}`).sort(),
    filesVerified: manifest.files.length,
  };
}
