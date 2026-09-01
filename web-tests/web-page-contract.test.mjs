import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const webRoot = new URL("../app/src/main/assets/web/", import.meta.url);

async function readWebFile(name) {
  return readFile(new URL(name, webRoot), "utf8");
}

async function readWebSources(names) {
  return (await Promise.all(names.map(readWebFile))).join("\n");
}

function tagWithId(html, tagName, id) {
  const match = html.match(new RegExp(`<${tagName}\\b[^>]*\\bid=["']${id}["'][^>]*>`, "i"));
  assert.ok(match, `missing <${tagName}> with id=${id}`);
  return match[0];
}

function cssRule(css, selector) {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = css.match(new RegExp(`${escaped}\\s*\\{([^}]*)\\}`));
  assert.ok(match, `missing CSS rule for ${selector}`);
  return match[1];
}

test("page ships the required local entry files", async () => {
  const files = await Promise.allSettled([
    readWebFile("index.html"),
    readWebFile("styles.css"),
    readWebFile("app.mjs"),
  ]);

  assert.deepEqual(files.map(({ status }) => status), ["fulfilled", "fulfilled", "fulfilled"]);
});

test("page declares the responsive shell and every controller mount point", async () => {
  const html = await readWebFile("index.html");
  assert.match(html, /<meta\s+name=["']viewport["']\s+content=["']width=device-width,\s*initial-scale=1["']\s*\/?>/i);
  assert.match(html, /<meta\s+name=["']referrer["']\s+content=["']no-referrer["']\s*\/?>/i);

  const requiredIds = [
    "pairing-view", "access-code", "connect-button", "pairing-status",
    "vault-view", "sidebar", "search-input", "current-filter", "refresh-button",
    "add-credential-button", "credential-list", "loading-state", "empty-state",
    "disconnect-banner", "manage-taxonomy-button", "credential-dialog",
    "credential-form", "credential-dialog-title", "credential-name", "credential-account",
    "credential-password", "credential-url", "credential-category", "credential-tags",
    "credential-notes", "credential-form-status", "taxonomy-dialog", "category-list",
    "tag-list", "new-category-name", "new-tag-name", "confirm-dialog", "confirm-title",
    "confirm-message", "confirm-button", "toast-region",
  ];
  for (const id of requiredIds) assert.match(html, new RegExp(`\\bid=["']${id}["']`), `missing #${id}`);
});

test("page loads only the local module, stylesheet and Noble import map", async () => {
  const html = await readWebFile("index.html");
  assert.match(html, /<link\b[^>]*\brel=["']stylesheet["'][^>]*\bhref=["']\/styles\.css["'][^>]*>/i);
  assert.match(html, /<script\b[^>]*\btype=["']module["'][^>]*\bsrc=["']\/app\.mjs["'][^>]*><\/script>/i);
  assert.match(html, /<script\b[^>]*\btype=["']importmap["'][^>]*>[\s\S]*?["']@noble\/curves\/["']\s*:\s*["']\/node_modules\/@noble\/curves\/["'][\s\S]*?<\/script>/i);
  assert.match(html, /["']@noble\/hashes\/["']\s*:\s*["']\/node_modules\/@noble\/hashes\/["']/i);
  assert.match(html, /["']@noble\/ciphers\/["']\s*:\s*["']\/node_modules\/@noble\/ciphers\/["']/i);
});

test("pairing and credential controls use safe input types and accessible labels", async () => {
  const html = await readWebFile("index.html");
  const accessCode = tagWithId(html, "input", "access-code");
  assert.match(accessCode, /\btype=["']text["']/i);
  assert.match(accessCode, /\binputmode=["']numeric["']/i);
  assert.match(accessCode, /\bmaxlength=["']6["']/i);

  const password = tagWithId(html, "input", "credential-password");
  assert.match(password, /\btype=["']password["']/i);
  for (const id of [
    "access-code", "search-input", "credential-name", "credential-account",
    "credential-password", "credential-url", "credential-category", "credential-notes",
    "new-category-name", "new-tag-name",
  ]) {
    assert.match(html, new RegExp(`<label\\b[^>]*\\bfor=["']${id}["']`, "i"), `missing label for #${id}`);
  }
  assert.match(html, /\bid=["']credential-tags["'][^>]*\brole=["']group["'][^>]*\baria-labelledby=["'][^"']+["']/i);
  assert.match(html, /\bid=["']toast-region["'][^>]*\baria-live=["']polite["']/i);
});

test("page is local-only and has no browser persistence or native Web Crypto", async () => {
  const sources = await readWebSources(["index.html", "styles.css", "app.mjs"]);
  assert.doesNotMatch(sources, /https?:\/\//i);
  assert.doesNotMatch(sources, /localStorage|sessionStorage|indexedDB|serviceWorker/i);
  assert.doesNotMatch(sources, /crypto\.subtle/i);
  assert.doesNotMatch(sources, /@import\s|url\(\s*["']?\/\//i);
});

test("page sources avoid unsafe dynamic HTML, inline handlers and sensitive diagnostics", async () => {
  const sources = await readWebSources(["index.html", "styles.css", "app.mjs"]);
  assert.doesNotMatch(sources, /\b(?:innerHTML|outerHTML|insertAdjacentHTML)\b/);
  assert.doesNotMatch(sources, /\son[a-z]+\s*=/i);
  assert.doesNotMatch(sources, /\bconsole\.(?:log|info|debug|warn|error)\s*\(/);
  assert.doesNotMatch(sources, /\b(?:data-[\w-]+|dataset)\b/i);
});

test("desktop credential table scrolls at every width while mobile cards stay unbounded", async () => {
  const css = await readWebFile("styles.css");
  assert.match(cssRule(css, ".credential-list"), /overflow-x\s*:\s*auto/i);
  const mobile = css.match(/@media\s*\(max-width:\s*760px\)\s*\{([\s\S]*)/i)?.[1] ?? "";
  assert.match(mobile, /\.credential-list\s*\{[\s\S]*?overflow\s*:\s*visible/i);
});

test("async dialog mutations use generation-scoped pending operations and guarded cancellation", async () => {
  const app = await readWebFile("app.mjs");
  for (const scope of ["credential", "confirmation", "taxonomy"]) {
    assert.match(app, new RegExp(`${scope}Operation`), `missing ${scope} pending operation`);
  }
  assert.match(app, /let\s+uiGeneration\s*=\s*0/);
  assert.match(app, /function\s+isOperationCurrent\s*\(/);
  assert.match(app, /function\s+invalidateUiOperations\s*\(/);
  assert.match(app, /if\s*\(\s*!isOperationCurrent\([^)]*\)\s*\)\s*return/g);
  assert.match(app, /credentialDialog\.addEventListener\("cancel"[\s\S]*?preventDefault\(\)/);
  assert.match(app, /taxonomyDialog\.addEventListener\("cancel"[\s\S]*?preventDefault\(\)/);
  assert.match(app, /confirmDialog\.addEventListener\("cancel"[\s\S]*?preventDefault\(\)/);
});

test("taxonomy mutations lock all related controls and only current continuations clear input", async () => {
  const app = await readWebFile("app.mjs");
  assert.match(app, /function\s+setTaxonomyPending\s*\(/);
  assert.match(app, /function\s+runTaxonomyMutation\s*\(/);
  assert.match(app, /if\s*\(\s*taxonomyOperation\s*!==\s*null\s*\)\s*return/);
  assert.match(app, /if\s*\(\s*!isOperationCurrent\("taxonomy",\s*token\)\s*\)\s*return;[\s\S]*?input\.value\s*=\s*""/);
  assert.match(app, /taxonomyDialog\.querySelectorAll\("input, button"\)/);
});

test("credential grid exposes table semantics, visually hidden desktop labels and contextual actions", async () => {
  const html = await readWebFile("index.html");
  const css = await readWebFile("styles.css");
  const app = await readWebFile("app.mjs");
  const list = tagWithId(html, "div", "credential-list");
  assert.match(list, /\brole=["']table["']/i);
  assert.match(cssRule(css, ".visually-hidden"), /clip\s*:/i);
  assert.doesNotMatch(cssRule(css, ".field-label"), /display\s*:\s*none/i);
  assert.match(app, /setAttribute\("role",\s*"row"\)/);
  assert.match(app, /setAttribute\("role",\s*"columnheader"\)/);
  assert.match(app, /setAttribute\("role",\s*"cell"\)/);
  assert.match(app, /context\.textContent\s*=\s*credentialName/);
});

test("runtime catalog exactly covers the local browser graph and every vendored module", async () => {
  const catalogText = await readWebFile("runtime-assets.tsv");
  const catalog = parseRuntimeCatalog(catalogText);
  const vendorModules = await listJavaScriptFiles(new URL("node_modules/@noble/", webRoot));
  const expected = new Set([
    "styles.css",
    "app.mjs",
    "lan-client.mjs",
    "lan-crypto.mjs",
    "vault-ui-model.mjs",
    ...vendorModules.map((entry) => `node_modules/@noble/${entry}`),
  ]);

  assert.deepEqual(new Set(catalog.keys()), expected);
  for (const [relativePath, mime] of catalog) {
    assert.equal(
      mime,
      relativePath.endsWith(".css")
        ? "text/css; charset=utf-8"
        : "text/javascript; charset=utf-8",
      `wrong MIME for ${relativePath}`,
    );
    assert.ok((await readFile(new URL(relativePath, webRoot))).byteLength > 0, `${relativePath} must exist and be non-empty`);
  }

  const browserRequests = await collectBrowserRequests();
  for (const requestPath of browserRequests) {
    assert.ok(catalog.has(requestPath), `browser request is absent from runtime catalog: ${requestPath}`);
  }
});

function parseRuntimeCatalog(source) {
  const entries = new Map();
  for (const [index, line] of source.split(/\r?\n/).entries()) {
    if (line.trim() === "" || line.trimStart().startsWith("#")) continue;
    const columns = line.split("\t");
    assert.equal(columns.length, 2, `catalog line ${index + 1} must have exactly two columns`);
    const [relativePath, mime] = columns;
    assert.ok(relativePath && mime, `catalog line ${index + 1} contains an empty column`);
    assert.ok(!entries.has(relativePath), `duplicate catalog path: ${relativePath}`);
    entries.set(relativePath, mime);
  }
  return entries;
}

async function listJavaScriptFiles(root, prefix = "") {
  const entries = await readdir(root, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const relativePath = path.posix.join(prefix, entry.name);
    if (entry.isDirectory()) {
      files.push(...await listJavaScriptFiles(new URL(`${entry.name}/`, root), relativePath));
    } else if (entry.isFile() && entry.name.endsWith(".js")) {
      files.push(relativePath);
    }
  }
  return files.sort();
}

async function collectBrowserRequests() {
  const html = await readWebFile("index.html");
  const importMapMatch = html.match(/<script\b[^>]*\btype=["']importmap["'][^>]*>([\s\S]*?)<\/script>/i);
  assert.ok(importMapMatch, "missing import map");
  const importMap = JSON.parse(importMapMatch[1]).imports;
  const pending = [...html.matchAll(/\b(?:src|href)=["'](\/[^"']+)["']/gi)]
    .map((match) => match[1].slice(1));
  for (const match of html.matchAll(/<script\b[^>]*\btype=["']importmap["'][^>]*>([\s\S]*?)<\/script>/gi)) {
    const mappings = Object.values(JSON.parse(match[1]).imports ?? {});
    for (const target of mappings) assert.match(target, /^\/[^?#]+\/$/, `import-map target must be local: ${target}`);
  }

  const visited = new Set();
  while (pending.length > 0) {
    const relativePath = pending.shift();
    if (visited.has(relativePath)) continue;
    visited.add(relativePath);
    const source = await readWebFile(relativePath);
    if (relativePath.endsWith(".css")) {
      for (const match of source.matchAll(/url\(\s*["']?([^"')]+)["']?\s*\)/gi)) {
        const target = match[1];
        if (/^(?:data:|https?:|#)/i.test(target)) continue;
        pending.push(resolveBrowserSpecifier(target, relativePath, importMap));
      }
    } else if (/\.(?:mjs|js)$/.test(relativePath)) {
      const staticImports = /(?:\bimport\s+(?:[^"'()]*?\s+from\s*)?|\bexport\s+[^"'()]*?\s+from\s*)["']([^"']+)["']/g;
      for (const match of source.matchAll(staticImports)) {
        pending.push(resolveBrowserSpecifier(match[1], relativePath, importMap));
      }
    }
  }
  return visited;
}

function resolveBrowserSpecifier(specifier, importer, importMap) {
  if (specifier.startsWith("/")) return specifier.slice(1);
  if (specifier.startsWith(".")) {
    return new URL(specifier, `https://vault.invalid/${importer}`).pathname.slice(1);
  }
  const mapping = Object.keys(importMap)
    .filter((candidate) => specifier === candidate || (candidate.endsWith("/") && specifier.startsWith(candidate)))
    .sort((left, right) => right.length - left.length)[0];
  assert.ok(mapping, `bare import has no import-map entry: ${specifier}`);
  return `${importMap[mapping]}${specifier.slice(mapping.length)}`.replace(/^\//, "");
}
