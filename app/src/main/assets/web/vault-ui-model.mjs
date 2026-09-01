export const ALL_CATEGORIES = "all";
export const UNCATEGORIZED = "uncategorized";

export function emptySnapshot() {
  return { revision: 0, credentials: [], categories: [], tags: [] };
}

export function normalizeSnapshot(value) {
  const source = requireObject(value, "snapshot");
  const revision = requireTimestamp(source.revision, "revision");
  const credentials = copyCollection(source.credentials, "credentials", copyCredential);
  const categories = copyCollection(source.categories, "categories", copyTaxonomy);
  const tags = copyCollection(source.tags, "tags", copyTaxonomy);

  return { revision, credentials, categories, tags };
}

export function filterCredentials(snapshot, filters = {}) {
  const query = normalizeSearch(filters?.query);
  const categoryId = filters?.categoryId;
  const tagId = filters?.tagId;
  const categories = new Map(snapshot.categories.map((category) => [category.id, category]));
  const tags = new Map(snapshot.tags.map((tag) => [tag.id, tag]));

  return snapshot.credentials.filter((credential) => {
    if (!matchesCategory(credential, categoryId)) return false;
    if (tagId != null && !credential.tagIds.includes(tagId)) return false;
    return matchesQuery(credential, query, categories, tags);
  });
}

export function credentialFormValue(credential) {
  return {
    name: credential.name,
    account: credential.account ?? "",
    password: credential.password,
    url: credential.url ?? "",
    categoryId: credential.categoryId ?? "",
    tagIds: [...credential.tagIds],
    notes: credential.notes ?? "",
  };
}

export function credentialCreateCommand(form) {
  return { op: "credential.create", ...credentialDraft(form) };
}

export function credentialUpdateCommand(credential, form) {
  return {
    op: "credential.update",
    id: credential.id,
    expectedVersion: credential.version,
    ...credentialDraft(form),
  };
}

export function credentialDeleteCommand(credential) {
  return { op: "credential.delete", id: credential.id, expectedVersion: credential.version };
}

export function categoryCreateCommand(name) {
  return { op: "category.create", name: trimText(name) };
}

export function categoryRenameCommand(category, name) {
  return {
    op: "category.rename",
    id: category.id,
    expectedVersion: category.version,
    name: trimText(name),
  };
}

export function categoryDeleteCommand(category) {
  return { op: "category.delete", id: category.id, expectedVersion: category.version };
}

export function tagCreateCommand(name) {
  return { op: "tag.create", name: trimText(name) };
}

export function tagRenameCommand(tag, name) {
  return {
    op: "tag.rename",
    id: tag.id,
    expectedVersion: tag.version,
    name: trimText(name),
  };
}

export function tagDeleteCommand(tag) {
  return { op: "tag.delete", id: tag.id, expectedVersion: tag.version };
}

export function reconcileRevealedIds(revealedIds, snapshot) {
  const currentIds = new Set(snapshot.credentials.map((credential) => credential.id));
  const reconciled = new Set();
  for (const id of revealedIds) {
    if (currentIds.has(id)) reconciled.add(id);
  }
  return reconciled;
}

function copyCredential(value) {
  const source = requireObject(value, "credential");
  return {
    id: requireId(source.id, "credential.id"),
    name: requireString(source.name, "credential.name"),
    account: requireNullableString(source.account, "credential.account"),
    password: requireString(source.password, "credential.password"),
    url: requireNullableString(source.url, "credential.url"),
    categoryId: requireNullableId(source.categoryId, "credential.categoryId"),
    tagIds: copyIds(source.tagIds, "credential.tagIds"),
    notes: requireNullableString(source.notes, "credential.notes"),
    version: requireVersion(source.version, "credential.version"),
    createdAt: requireTimestamp(source.createdAt, "credential.createdAt"),
    updatedAt: requireTimestamp(source.updatedAt, "credential.updatedAt"),
  };
}

function copyTaxonomy(value) {
  const source = requireObject(value, "taxonomy");
  return {
    id: requireId(source.id, "taxonomy.id"),
    name: requireString(source.name, "taxonomy.name"),
    version: requireVersion(source.version, "taxonomy.version"),
  };
}

function copyCollection(value, name, copyItem) {
  if (!Array.isArray(value)) throw new TypeError(`${name} must be an array`);
  const ids = new Set();
  return value.map((item) => {
    const copied = copyItem(item);
    if (ids.has(copied.id)) throw new TypeError(`${name} contains duplicate IDs`);
    ids.add(copied.id);
    return copied;
  });
}

function copyIds(value, name) {
  if (!Array.isArray(value)) throw new TypeError(`${name} must be an array`);
  const seen = new Set();
  return value.map((id) => {
    const validId = requireId(id, name);
    if (seen.has(validId)) throw new TypeError(`${name} contains duplicate IDs`);
    seen.add(validId);
    return validId;
  });
}

function credentialDraft(form) {
  const source = form ?? {};
  return {
    name: trimText(source.name),
    account: trimToNull(source.account),
    password: rawText(source.password),
    url: trimToNull(source.url),
    categoryId: trimToNull(source.categoryId),
    tagIds: deduplicateIds(source.tagIds),
    notes: trimToNull(source.notes),
  };
}

function deduplicateIds(value) {
  const ids = Array.isArray(value) ? value : [];
  const unique = new Set();
  for (const id of ids) unique.add(id);
  return [...unique];
}

function matchesCategory(credential, categoryId) {
  return categoryId == null || categoryId === ALL_CATEGORIES
    || (categoryId === UNCATEGORIZED
      ? credential.categoryId === null
      : credential.categoryId === categoryId);
}

function matchesQuery(credential, query, categories, tags) {
  if (query === "") return true;
  if (contains(credential.name, query) || contains(credential.account, query) || contains(credential.url, query)) return true;
  if (credential.categoryId !== null && contains(categories.get(credential.categoryId)?.name, query)) return true;
  return credential.tagIds.some((tagId) => contains(tags.get(tagId)?.name, query));
}

function contains(value, query) {
  return normalizeSearch(value).includes(query);
}

function normalizeSearch(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function trimText(value) {
  return typeof value === "string" ? value.trim() : "";
}

function trimToNull(value) {
  const trimmed = trimText(value);
  return trimmed === "" ? null : trimmed;
}

function rawText(value) {
  return typeof value === "string" ? value : "";
}

function requireObject(value, name) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new TypeError(`${name} must be an object`);
  return value;
}

function requireId(value, name) {
  if (typeof value !== "string" || value.trim() === "") throw new TypeError(`${name} must be a non-empty string`);
  return value;
}

function requireNullableId(value, name) {
  return value === null ? null : requireId(value, name);
}

function requireString(value, name) {
  if (typeof value !== "string") throw new TypeError(`${name} must be a string`);
  return value;
}

function requireNullableString(value, name) {
  return value === null ? null : requireString(value, name);
}

function requireVersion(value, name) {
  if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`${name} must be a positive integer`);
  return value;
}

function requireTimestamp(value, name) {
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${name} must be a non-negative timestamp`);
  return value;
}
