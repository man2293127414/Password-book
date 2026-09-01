import assert from "node:assert/strict";
import test from "node:test";

import {
  ALL_CATEGORIES,
  UNCATEGORIZED,
  credentialCreateCommand,
  credentialDeleteCommand,
  credentialFormValue,
  credentialUpdateCommand,
  categoryCreateCommand,
  categoryDeleteCommand,
  categoryRenameCommand,
  emptySnapshot,
  filterCredentials,
  normalizeSnapshot,
  reconcileRevealedIds,
  tagCreateCommand,
  tagDeleteCommand,
  tagRenameCommand,
} from "../app/src/main/assets/web/vault-ui-model.mjs";

function wireSnapshot() {
  return {
    revision: 7,
    credentials: [
      {
        id: "cred-1",
        name: "  邮箱  ",
        account: "Me@Example.com",
        password: "secret-only",
        url: "https://mail.example.com",
        categoryId: "cat-1",
        tagIds: ["tag-1", "tag-2"],
        notes: "notes-only",
        version: 3,
        createdAt: 100,
        updatedAt: 200,
      },
      {
        id: "cred-2",
        name: "银行",
        account: null,
        password: "bank-password",
        url: null,
        categoryId: null,
        tagIds: [],
        notes: null,
        version: 1,
        createdAt: 300,
        updatedAt: 400,
      },
      {
        id: "cred-3",
        name: "备用",
        account: "other",
        password: "other-password",
        url: "https://other.example.com",
        categoryId: "cat-2",
        tagIds: ["tag-3"],
        notes: null,
        version: 2,
        createdAt: 500,
        updatedAt: 600,
      },
    ],
    categories: [
      { id: "cat-1", name: "工作 Mail", version: 2 },
      { id: "cat-2", name: "个人", version: 1 },
    ],
    tags: [
      { id: "tag-1", name: "重要", version: 4 },
      { id: "tag-2", name: "Email", version: 1 },
      { id: "tag-3", name: "备用", version: 1 },
    ],
  };
}

function ids(credentials) {
  return credentials.map((credential) => credential.id);
}

const snapshot = normalizeSnapshot(wireSnapshot());

test("emptySnapshot creates an independent empty wire-model shape", () => {
  const first = emptySnapshot();
  const second = emptySnapshot();

  assert.deepEqual(first, { revision: 0, credentials: [], categories: [], tags: [] });
  assert.notStrictEqual(first, second);
  assert.notStrictEqual(first.credentials, second.credentials);
});

test("normalizeSnapshot copies every nested collection without changing valid wire values", () => {
  const source = wireSnapshot();
  const normalized = normalizeSnapshot(source);

  assert.deepEqual(normalized, source);
  assert.notStrictEqual(normalized, source);
  assert.notStrictEqual(normalized.credentials, source.credentials);
  assert.notStrictEqual(normalized.credentials[0], source.credentials[0]);
  assert.notStrictEqual(normalized.credentials[0].tagIds, source.credentials[0].tagIds);
  assert.notStrictEqual(normalized.categories, source.categories);
  assert.notStrictEqual(normalized.categories[0], source.categories[0]);
  assert.notStrictEqual(normalized.tags, source.tags);
  assert.notStrictEqual(normalized.tags[0], source.tags[0]);

  source.credentials[0].tagIds.push("tag-3");
  source.categories[0].name = "changed";
  assert.deepEqual(normalized.credentials[0].tagIds, ["tag-1", "tag-2"]);
  assert.equal(normalized.categories[0].name, "工作 Mail");
});

test("normalizeSnapshot rejects malformed wire fields and duplicate IDs", () => {
  const cases = [
    null,
    { ...wireSnapshot(), revision: "7" },
    { ...wireSnapshot(), credentials: [{ ...wireSnapshot().credentials[0], id: "" }] },
    { ...wireSnapshot(), credentials: [{ ...wireSnapshot().credentials[0], version: 0 }] },
    { ...wireSnapshot(), credentials: [{ ...wireSnapshot().credentials[0], createdAt: "100" }] },
    { ...wireSnapshot(), credentials: [{ ...wireSnapshot().credentials[0], account: 9 }] },
    { ...wireSnapshot(), credentials: [{ ...wireSnapshot().credentials[0], password: null }] },
    { ...wireSnapshot(), credentials: [{ ...wireSnapshot().credentials[0], url: false }] },
    { ...wireSnapshot(), credentials: [{ ...wireSnapshot().credentials[0], categoryId: undefined }] },
    { ...wireSnapshot(), credentials: [{ ...wireSnapshot().credentials[0], notes: {} }] },
    { ...wireSnapshot(), credentials: [{ ...wireSnapshot().credentials[0], tagIds: ["tag-1", "tag-1"] }] },
    { ...wireSnapshot(), credentials: [{ ...wireSnapshot().credentials[0], tagIds: [null] }] },
    { ...wireSnapshot(), credentials: [wireSnapshot().credentials[0], { ...wireSnapshot().credentials[0] }] },
    { ...wireSnapshot(), categories: [wireSnapshot().categories[0], { ...wireSnapshot().categories[0] }] },
    { ...wireSnapshot(), tags: [wireSnapshot().tags[0], { ...wireSnapshot().tags[0] }] },
    { ...wireSnapshot(), categories: [{ ...wireSnapshot().categories[0], name: null }] },
    { ...wireSnapshot(), tags: [{ ...wireSnapshot().tags[0], version: "1" }] },
  ];

  for (const value of cases) {
    assert.throws(() => normalizeSnapshot(value), TypeError);
  }
});

test("search matches names accounts URLs and resolved taxonomy names in source order", () => {
  assert.deepEqual(ids(filterCredentials(snapshot, { query: " 邮箱 " })), ["cred-1"]);
  assert.deepEqual(ids(filterCredentials(snapshot, { query: "me@example" })), ["cred-1"]);
  assert.deepEqual(ids(filterCredentials(snapshot, { query: "MAIL.EXAMPLE" })), ["cred-1"]);
  assert.deepEqual(ids(filterCredentials(snapshot, { query: "工作 mail" })), ["cred-1"]);
  assert.deepEqual(ids(filterCredentials(snapshot, { query: "重要" })), ["cred-1"]);
  assert.deepEqual(ids(filterCredentials(snapshot, { query: "备用" })), ["cred-3"]);
});

test("search excludes password and notes and combines with taxonomy filters", () => {
  assert.deepEqual(ids(filterCredentials(snapshot, { query: "mail", categoryId: "cat-1" })), ["cred-1"]);
  assert.deepEqual(ids(filterCredentials(snapshot, { query: "secret-only", categoryId: ALL_CATEGORIES })), []);
  assert.deepEqual(ids(filterCredentials(snapshot, { query: "notes-only", tagId: null })), []);
  assert.deepEqual(ids(filterCredentials(snapshot, { query: "mail", tagId: "tag-2" })), ["cred-1"]);
  assert.deepEqual(ids(filterCredentials(snapshot, { query: "mail", tagId: "tag-3" })), []);
});

test("category and tag filters use AND semantics and uncategorized only matches null", () => {
  assert.deepEqual(ids(filterCredentials(snapshot, { categoryId: ALL_CATEGORIES })), ["cred-1", "cred-2", "cred-3"]);
  assert.deepEqual(ids(filterCredentials(snapshot, { categoryId: UNCATEGORIZED })), ["cred-2"]);
  assert.deepEqual(ids(filterCredentials(snapshot, { categoryId: "cat-1", tagId: "tag-1" })), ["cred-1"]);
  assert.deepEqual(ids(filterCredentials(snapshot, { categoryId: "cat-1", tagId: "tag-3" })), []);
});

test("credential forms trim permitted fields, preserve password, null optional blanks and deduplicate tags", () => {
  const form = {
    name: "  邮箱  ",
    account: "  me@example.com  ",
    password: "  exact secret  ",
    url: "  https://example.com  ",
    categoryId: "",
    tagIds: ["tag-1", "tag-2", "tag-1"],
    notes: "   ",
  };

  assert.deepEqual(credentialFormValue(snapshot.credentials[0]), {
    name: "  邮箱  ",
    account: "Me@Example.com",
    password: "secret-only",
    url: "https://mail.example.com",
    categoryId: "cat-1",
    tagIds: ["tag-1", "tag-2"],
    notes: "notes-only",
  });
  assert.deepEqual(credentialCreateCommand(form), {
    op: "credential.create",
    name: "邮箱",
    account: "me@example.com",
    password: "  exact secret  ",
    url: "https://example.com",
    categoryId: null,
    tagIds: ["tag-1", "tag-2"],
    notes: null,
  });
});

test("credential commands use current entity version and exact LAN fields", () => {
  const form = {
    name: "邮箱",
    account: "me@example.com",
    password: "new-secret",
    url: "https://example.com",
    categoryId: "cat-1",
    tagIds: ["tag-1"],
    notes: "",
  };

  assert.deepEqual(credentialUpdateCommand(snapshot.credentials[0], form), {
    op: "credential.update",
    id: "cred-1",
    expectedVersion: 3,
    name: "邮箱",
    account: "me@example.com",
    password: "new-secret",
    url: "https://example.com",
    categoryId: "cat-1",
    tagIds: ["tag-1"],
    notes: null,
  });
  assert.deepEqual(credentialDeleteCommand(snapshot.credentials[0]), {
    op: "credential.delete",
    id: "cred-1",
    expectedVersion: 3,
  });
});

test("category and tag mutation commands match the LAN dispatcher protocol", () => {
  assert.deepEqual(categoryCreateCommand("  工作  "), { op: "category.create", name: "工作" });
  assert.deepEqual(categoryRenameCommand(snapshot.categories[0], "  新工作  "), {
    op: "category.rename", id: "cat-1", expectedVersion: 2, name: "新工作",
  });
  assert.deepEqual(categoryDeleteCommand(snapshot.categories[0]), {
    op: "category.delete", id: "cat-1", expectedVersion: 2,
  });
  assert.deepEqual(tagCreateCommand("  重要  "), { op: "tag.create", name: "重要" });
  assert.deepEqual(tagRenameCommand(snapshot.tags[0], "  紧急  "), {
    op: "tag.rename", id: "tag-1", expectedVersion: 4, name: "紧急",
  });
  assert.deepEqual(tagDeleteCommand(snapshot.tags[0]), {
    op: "tag.delete", id: "tag-1", expectedVersion: 4,
  });
});

test("reconcileRevealedIds returns only IDs still present without changing the input set", () => {
  const revealed = new Set(["cred-2", "gone", "cred-1"]);
  const reconciled = reconcileRevealedIds(revealed, snapshot);

  assert.deepEqual([...reconciled], ["cred-2", "cred-1"]);
  assert.deepEqual([...revealed], ["cred-2", "gone", "cred-1"]);
  assert.notStrictEqual(reconciled, revealed);
});
