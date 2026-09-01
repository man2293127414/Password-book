import { LanApiError, LanVaultClient } from "./lan-client.mjs";
import {
  ALL_CATEGORIES,
  UNCATEGORIZED,
  categoryCreateCommand,
  categoryDeleteCommand,
  categoryRenameCommand,
  credentialCreateCommand,
  credentialDeleteCommand,
  credentialFormValue,
  credentialUpdateCommand,
  emptySnapshot,
  filterCredentials,
  reconcileRevealedIds,
  tagCreateCommand,
  tagDeleteCommand,
  tagRenameCommand,
} from "./vault-ui-model.mjs";

const MASKED_PASSWORD = "••••••••";
const DISCONNECTED_MESSAGE = "与手机连接已断开，请在手机重新开启 PC 访问";
const STALE_MESSAGE = "记录已变化，请刷新后重试";
const NOT_FOUND_MESSAGE = "记录已不存在，已刷新列表";
const GENERIC_MESSAGE = "操作失败，请稍后重试";

const byId = (id) => document.getElementById(id);
const elements = {
  pairingView: byId("pairing-view"),
  pairingForm: byId("pairing-form"),
  accessCode: byId("access-code"),
  connectButton: byId("connect-button"),
  pairingStatus: byId("pairing-status"),
  vaultView: byId("vault-view"),
  vaultContent: byId("vault-content"),
  disconnectBanner: byId("disconnect-banner"),
  filterNavigation: byId("filter-navigation"),
  searchInput: byId("search-input"),
  currentFilter: byId("current-filter"),
  refreshButton: byId("refresh-button"),
  addCredentialButton: byId("add-credential-button"),
  manageTaxonomyButton: byId("manage-taxonomy-button"),
  credentialList: byId("credential-list"),
  loadingState: byId("loading-state"),
  emptyState: byId("empty-state"),
  credentialDialog: byId("credential-dialog"),
  credentialForm: byId("credential-form"),
  credentialDialogTitle: byId("credential-dialog-title"),
  credentialName: byId("credential-name"),
  credentialAccount: byId("credential-account"),
  credentialPassword: byId("credential-password"),
  credentialUrl: byId("credential-url"),
  credentialCategory: byId("credential-category"),
  credentialTagOptions: byId("credential-tag-options"),
  credentialNotes: byId("credential-notes"),
  credentialFormStatus: byId("credential-form-status"),
  credentialSaveButton: byId("credential-save-button"),
  credentialCancelButton: byId("credential-cancel-button"),
  credentialCloseButton: byId("credential-close-button"),
  taxonomyDialog: byId("taxonomy-dialog"),
  taxonomyCloseButton: byId("taxonomy-close-button"),
  categoryCreateForm: byId("category-create-form"),
  newCategoryName: byId("new-category-name"),
  categoryList: byId("category-list"),
  tagCreateForm: byId("tag-create-form"),
  newTagName: byId("new-tag-name"),
  tagList: byId("tag-list"),
  taxonomyStatus: byId("taxonomy-status"),
  confirmDialog: byId("confirm-dialog"),
  confirmTitle: byId("confirm-title"),
  confirmMessage: byId("confirm-message"),
  confirmStatus: byId("confirm-status"),
  confirmButton: byId("confirm-button"),
  confirmCancelButton: byId("confirm-cancel-button"),
  toastRegion: byId("toast-region"),
};

let snapshot = emptySnapshot();
let revealedIds = new Set();
let filterState = { categoryId: ALL_CATEGORIES, tagId: null, query: "" };
let editingCredentialId = null;
let pendingConfirmation = null;
let pairingInProgress = false;
let toastTimer = null;
let uiGeneration = 0;
let operationSequence = 0;
let credentialOperation = null;
let confirmationOperation = null;
let taxonomyOperation = null;
let refreshOperation = null;
let pairingOperation = null;

const client = new LanVaultClient({
  onDisconnect: () => enterDisconnectedState(),
});

function makeElement(tagName, className, text) {
  const node = document.createElement(tagName);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function setStatus(node, message = "") {
  node.textContent = message;
}

function setButtonBusy(button, busy, busyText, idleText) {
  button.disabled = busy;
  button.textContent = busy ? busyText : idleText;
}

function currentOperation(scope) {
  if (scope === "credential") return credentialOperation;
  if (scope === "confirmation") return confirmationOperation;
  if (scope === "taxonomy") return taxonomyOperation;
  if (scope === "refresh") return refreshOperation;
  if (scope === "pairing") return pairingOperation;
  throw new TypeError("unknown UI operation scope");
}

function setCurrentOperation(scope, token) {
  if (scope === "credential") credentialOperation = token;
  else if (scope === "confirmation") confirmationOperation = token;
  else if (scope === "taxonomy") taxonomyOperation = token;
  else if (scope === "refresh") refreshOperation = token;
  else if (scope === "pairing") pairingOperation = token;
  else throw new TypeError("unknown UI operation scope");
}

function beginOperation(scope) {
  if (currentOperation(scope) !== null) return null;
  const token = { sequence: ++operationSequence, generation: uiGeneration };
  setCurrentOperation(scope, token);
  return token;
}

function isOperationCurrent(scope, token) {
  return token !== null
    && token.generation === uiGeneration
    && currentOperation(scope) === token;
}

function finishOperation(scope, token) {
  if (!isOperationCurrent(scope, token)) return false;
  setCurrentOperation(scope, null);
  return true;
}

function invalidateUiOperations() {
  uiGeneration += 1;
  credentialOperation = null;
  confirmationOperation = null;
  taxonomyOperation = null;
  refreshOperation = null;
  pairingOperation = null;
}

function setCredentialPending(pending) {
  for (const control of elements.credentialDialog.querySelectorAll("input, select, textarea, button")) {
    control.disabled = pending;
  }
  elements.credentialSaveButton.textContent = pending ? "保存中…" : "保存";
}

function setConfirmationPending(pending) {
  elements.confirmButton.disabled = pending;
  elements.confirmCancelButton.disabled = pending;
  elements.confirmButton.textContent = pending ? "处理中…" : "删除";
}

function setTaxonomyPending(pending) {
  for (const control of elements.taxonomyDialog.querySelectorAll("input, button")) {
    control.disabled = pending;
  }
}

function showToast(message) {
  if (toastTimer !== null) clearTimeout(toastTimer);
  elements.toastRegion.textContent = message;
  elements.toastRegion.hidden = false;
  toastTimer = setTimeout(() => {
    elements.toastRegion.textContent = "";
    elements.toastRegion.hidden = true;
    toastTimer = null;
  }, 2600);
}

function applySnapshot(nextSnapshot) {
  snapshot = nextSnapshot;
  revealedIds = reconcileRevealedIds(revealedIds, snapshot);
  if (
    filterState.categoryId !== ALL_CATEGORIES
    && filterState.categoryId !== UNCATEGORIZED
    && !snapshot.categories.some(({ id }) => id === filterState.categoryId)
  ) {
    filterState.categoryId = ALL_CATEGORIES;
  }
  if (filterState.tagId !== null && !snapshot.tags.some(({ id }) => id === filterState.tagId)) {
    filterState.tagId = null;
  }
  renderVault();
}

function renderVault() {
  renderFilters();
  renderCredentials();
  if (elements.taxonomyDialog.open) renderTaxonomyLists();
}

function renderFilters() {
  elements.filterNavigation.replaceChildren();
  const basicHeading = makeElement("p", "filter-heading", "密码");
  elements.filterNavigation.append(basicHeading);
  elements.filterNavigation.append(
    makeFilterButton("全部密码", filterState.categoryId === ALL_CATEGORIES && filterState.tagId === null, () => {
      filterState.categoryId = ALL_CATEGORIES;
      filterState.tagId = null;
      renderVault();
    }),
    makeFilterButton("未分类", filterState.categoryId === UNCATEGORIZED && filterState.tagId === null, () => {
      filterState.categoryId = UNCATEGORIZED;
      filterState.tagId = null;
      renderVault();
    }),
  );

  if (snapshot.categories.length > 0) {
    elements.filterNavigation.append(makeElement("p", "filter-heading", "分类"));
    for (const category of snapshot.categories) {
      elements.filterNavigation.append(makeFilterButton(
        category.name,
        filterState.categoryId === category.id && filterState.tagId === null,
        () => {
          filterState.categoryId = category.id;
          filterState.tagId = null;
          renderVault();
        },
      ));
    }
  }

  if (snapshot.tags.length > 0) {
    elements.filterNavigation.append(makeElement("p", "filter-heading", "标签"));
    for (const tag of snapshot.tags) {
      elements.filterNavigation.append(makeFilterButton(
        tag.name,
        filterState.tagId === tag.id,
        () => {
          filterState.categoryId = ALL_CATEGORIES;
          filterState.tagId = tag.id;
          renderVault();
        },
      ));
    }
  }
  elements.currentFilter.textContent = currentFilterLabel();
}

function makeFilterButton(label, active, activate) {
  const button = makeElement("button", "filter-button", label);
  button.type = "button";
  if (active) {
    button.classList.add("active");
    button.setAttribute("aria-current", "true");
  }
  button.addEventListener("click", activate);
  return button;
}

function currentFilterLabel() {
  if (filterState.tagId !== null) {
    return snapshot.tags.find(({ id }) => id === filterState.tagId)?.name ?? "全部密码";
  }
  if (filterState.categoryId === UNCATEGORIZED) return "未分类";
  if (filterState.categoryId === ALL_CATEGORIES) return "全部密码";
  return snapshot.categories.find(({ id }) => id === filterState.categoryId)?.name ?? "全部密码";
}

function renderCredentials() {
  const credentials = filterCredentials(snapshot, filterState);
  elements.credentialList.replaceChildren();
  elements.emptyState.hidden = credentials.length !== 0;
  elements.credentialList.hidden = credentials.length === 0;
  if (credentials.length === 0) return;

  const header = makeElement("div", "credential-header");
  header.setAttribute("role", "row");
  for (const label of ["名称", "账号", "密码", "网址", "分类与标签", "备注", "修改时间", "操作"]) {
    const column = makeElement("span", "", label);
    column.setAttribute("role", "columnheader");
    header.append(column);
  }
  elements.credentialList.append(header);
  for (const credential of credentials) elements.credentialList.append(renderCredential(credential));
}

function renderCredential(credential) {
  const categories = new Map(snapshot.categories.map((item) => [item.id, item.name]));
  const tags = new Map(snapshot.tags.map((item) => [item.id, item.name]));
  const taxonomy = [];
  if (credential.categoryId !== null) taxonomy.push(categories.get(credential.categoryId) ?? "未分类");
  for (const tagId of credential.tagIds) {
    const tagName = tags.get(tagId);
    if (tagName !== undefined) taxonomy.push(tagName);
  }

  const row = makeElement("article", "credential-row");
  row.setAttribute("role", "row");
  row.append(
    makeCredentialField("名称", credential.name, "credential-name"),
    makeCredentialField("账号", credential.account ?? "—"),
    makePasswordField(credential),
    makeCredentialField("网址", credential.url ?? "—"),
    makeCredentialField("分类与标签", taxonomy.length > 0 ? taxonomy.join(" · ") : "未分类"),
    makeCredentialField("备注", credential.notes ?? "—"),
    makeCredentialField("修改时间", formatTimestamp(credential.updatedAt)),
    makeCredentialActions(credential),
  );
  return row;
}

function makeCredentialField(label, value, extraClass = "") {
  const field = makeElement("div", `credential-field ${extraClass}`.trim());
  field.setAttribute("role", "cell");
  field.append(makeElement("span", "field-label", label), makeElement("span", "", value));
  return field;
}

function makePasswordField(credential) {
  const field = makeElement("div", "credential-field");
  field.setAttribute("role", "cell");
  field.append(makeElement("span", "field-label", "密码"));
  const password = makeElement(
    "span",
    "password-value",
    revealedIds.has(credential.id) ? credential.password : MASKED_PASSWORD,
  );
  field.append(password);
  return field;
}

function makeCredentialActions(credential) {
  const actions = makeElement("div", "credential-actions");
  actions.setAttribute("role", "cell");
  const copyAccount = makeActionButton("复制账号", async () => {
    if (credential.account === null || credential.account === "") {
      showToast("这条记录没有账号");
      return;
    }
    await copyWithFeedback(credential.account, "账号已复制");
  }, false, credential.name);
  const copyPassword = makeActionButton(
    "复制密码",
    () => copyWithFeedback(credential.password, "密码已复制"),
    false,
    credential.name,
  );
  const revealLabel = revealedIds.has(credential.id) ? "隐藏密码" : "显示密码";
  const reveal = makeActionButton(revealLabel, () => {
    if (revealedIds.has(credential.id)) revealedIds.delete(credential.id);
    else revealedIds.add(credential.id);
    renderCredentials();
  }, false, credential.name);
  const edit = makeActionButton("编辑", () => openCredentialDialog(credential), false, credential.name);
  const remove = makeActionButton(
    "删除",
    () => openDeleteCredentialConfirmation(credential),
    true,
    credential.name,
  );
  actions.append(copyAccount, copyPassword, reveal, edit, remove);
  return actions;
}

function makeActionButton(label, activate, danger = false, credentialName = null) {
  const button = makeElement("button", danger ? "row-action danger-text" : "row-action", label);
  button.type = "button";
  if (credentialName !== null) {
    const suffix = makeElement("span", "visually-hidden", "，记录：");
    const context = document.createElement("span");
    context.textContent = credentialName;
    suffix.append(context);
    button.append(suffix);
  }
  button.addEventListener("click", activate);
  return button;
}

function formatTimestamp(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

async function copyText(value) {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      return;
    } catch {
      // Continue to the user-gesture fallback available on private-IP HTTP.
    }
  }
  const field = document.createElement("textarea");
  field.value = value;
  field.setAttribute("readonly", "");
  field.className = "copy-buffer";
  document.body.append(field);
  try {
    field.select();
    if (!document.execCommand("copy")) throw new Error("COPY_FAILED");
  } finally {
    field.value = "";
    field.remove();
  }
}

async function copyWithFeedback(value, successMessage) {
  const generation = uiGeneration;
  try {
    await copyText(value);
    if (generation !== uiGeneration) return;
    showToast(successMessage);
  } catch {
    if (generation !== uiGeneration) return;
    showToast("复制失败，请重试");
  }
}

function openCredentialDialog(credential = null) {
  if (credentialOperation !== null || elements.credentialDialog.open) return;
  editingCredentialId = credential?.id ?? null;
  elements.credentialForm.reset();
  setStatus(elements.credentialFormStatus);
  elements.credentialDialogTitle.textContent = credential === null ? "新增密码" : "编辑密码";
  renderCredentialTaxonomyOptions();
  if (credential !== null) fillCredentialForm(credentialFormValue(credential));
  elements.credentialDialog.showModal();
  elements.credentialName.focus();
}

function renderCredentialTaxonomyOptions() {
  elements.credentialCategory.replaceChildren();
  const uncategorized = makeElement("option", "", "未分类");
  uncategorized.value = "";
  elements.credentialCategory.append(uncategorized);
  for (const category of snapshot.categories) {
    const option = makeElement("option", "", category.name);
    option.value = category.id;
    elements.credentialCategory.append(option);
  }

  elements.credentialTagOptions.replaceChildren();
  if (snapshot.tags.length === 0) {
    elements.credentialTagOptions.append(makeElement("span", "muted", "暂无标签"));
    return;
  }
  for (const tag of snapshot.tags) {
    const label = makeElement("label", "checkbox-option");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.value = tag.id;
    label.append(checkbox, makeElement("span", "", tag.name));
    elements.credentialTagOptions.append(label);
  }
}

function fillCredentialForm(value) {
  elements.credentialName.value = value.name;
  elements.credentialAccount.value = value.account;
  elements.credentialPassword.value = value.password;
  elements.credentialUrl.value = value.url;
  elements.credentialCategory.value = value.categoryId;
  elements.credentialNotes.value = value.notes;
  const selectedTags = new Set(value.tagIds);
  for (const checkbox of elements.credentialTagOptions.querySelectorAll('input[type="checkbox"]')) {
    checkbox.checked = selectedTags.has(checkbox.value);
  }
}

function readCredentialForm() {
  return {
    name: elements.credentialName.value,
    account: elements.credentialAccount.value,
    password: elements.credentialPassword.value,
    url: elements.credentialUrl.value,
    categoryId: elements.credentialCategory.value,
    tagIds: [...elements.credentialTagOptions.querySelectorAll('input[type="checkbox"]:checked')]
      .map((checkbox) => checkbox.value),
    notes: elements.credentialNotes.value,
  };
}

function clearCredentialForm() {
  editingCredentialId = null;
  elements.credentialForm.reset();
  elements.credentialName.value = "";
  elements.credentialAccount.value = "";
  elements.credentialPassword.value = "";
  elements.credentialUrl.value = "";
  elements.credentialNotes.value = "";
  elements.credentialCategory.replaceChildren();
  elements.credentialTagOptions.replaceChildren();
  setStatus(elements.credentialFormStatus);
}

async function submitCredential(event) {
  event.preventDefault();
  if (credentialOperation !== null) return;
  const form = readCredentialForm();
  if (form.name.trim() === "" || form.password === "") {
    setStatus(elements.credentialFormStatus, "名称和密码为必填项");
    return;
  }
  const token = beginOperation("credential");
  if (token === null) return;
  setCredentialPending(true);
  setStatus(elements.credentialFormStatus);
  try {
    const existing = editingCredentialId === null
      ? null
      : snapshot.credentials.find(({ id }) => id === editingCredentialId);
    if (editingCredentialId !== null && existing === undefined) {
      if (!isOperationCurrent("credential", token)) return;
      elements.credentialDialog.close();
      await refreshAfterStale("NOT_FOUND", "credential", token);
      return;
    }
    const command = existing === null
      ? credentialCreateCommand(form)
      : credentialUpdateCommand(existing, form);
    const nextSnapshot = await client.mutate(command);
    if (!isOperationCurrent("credential", token)) return;
    applySnapshot(nextSnapshot);
    elements.credentialDialog.close();
    showToast(existing === null ? "密码已新增" : "密码已更新");
  } catch (error) {
    if (!isOperationCurrent("credential", token)) return;
    await handleOperationError(error, {
      statusNode: elements.credentialFormStatus,
      closeStaleDialog: elements.credentialDialog,
      scope: "credential",
      token,
    });
  } finally {
    if (finishOperation("credential", token)) setCredentialPending(false);
  }
}

function openTaxonomyDialog() {
  if (taxonomyOperation !== null || elements.taxonomyDialog.open) return;
  elements.newCategoryName.value = "";
  elements.newTagName.value = "";
  setStatus(elements.taxonomyStatus);
  renderTaxonomyLists();
  elements.taxonomyDialog.showModal();
}

function renderTaxonomyLists() {
  renderTaxonomyCollection("category", snapshot.categories, elements.categoryList);
  renderTaxonomyCollection("tag", snapshot.tags, elements.tagList);
  setTaxonomyPending(taxonomyOperation !== null);
}

function renderTaxonomyCollection(kind, items, container) {
  container.replaceChildren();
  if (items.length === 0) {
    container.append(makeElement("p", "muted", kind === "category" ? "暂无分类" : "暂无标签"));
    return;
  }
  for (const item of items) {
    const row = makeElement("div", "taxonomy-item");
    const input = document.createElement("input");
    input.type = "text";
    input.value = item.name;
    input.setAttribute("aria-label", kind === "category" ? "分类名称" : "标签名称");
    const actions = makeElement("div", "taxonomy-actions");
    const rename = makeActionButton("重命名", () => {
      if (input.value.trim() === "") {
        setStatus(elements.taxonomyStatus, "名称不能为空");
        input.focus();
        return;
      }
      setStatus(elements.taxonomyStatus);
      const command = kind === "category"
        ? categoryRenameCommand(item, input.value)
        : tagRenameCommand(item, input.value);
      runTaxonomyMutation(
        command,
        kind === "category" ? "分类已重命名" : "标签已重命名",
      );
    });
    const remove = makeActionButton("删除", () => {
      openTaxonomyDeleteConfirmation(kind, item);
    }, true);
    actions.append(rename, remove);
    row.append(input, actions);
    container.append(row);
  }
}

async function createTaxonomy(kind, input) {
  if (taxonomyOperation !== null) return;
  const name = input.value;
  if (name.trim() === "") {
    setStatus(elements.taxonomyStatus, "名称不能为空");
    input.focus();
    return;
  }
  setStatus(elements.taxonomyStatus);
  const command = kind === "category" ? categoryCreateCommand(name) : tagCreateCommand(name);
  await runTaxonomyMutation(
    command,
    kind === "category" ? "分类已创建" : "标签已创建",
    input,
  );
}

async function runTaxonomyMutation(command, successMessage, input = null) {
  if (taxonomyOperation !== null) return;
  const token = beginOperation("taxonomy");
  if (token === null) return;
  setTaxonomyPending(true);
  try {
    const nextSnapshot = await client.mutate(command);
    if (!isOperationCurrent("taxonomy", token)) return;
    applySnapshot(nextSnapshot);
    if (!isOperationCurrent("taxonomy", token)) return;
    if (input !== null) input.value = "";
    showToast(successMessage);
  } catch (error) {
    if (!isOperationCurrent("taxonomy", token)) return;
    await handleOperationError(error, {
      statusNode: elements.taxonomyStatus,
      scope: "taxonomy",
      token,
    });
  } finally {
    if (finishOperation("taxonomy", token)) setTaxonomyPending(false);
  }
}

function openDeleteCredentialConfirmation(credential) {
  openConfirmation({
    title: "删除密码",
    message: "确定删除这条密码记录吗？此操作无法撤销。",
    command: credentialDeleteCommand(credential),
    successMessage: "密码已删除",
  });
}

function openTaxonomyDeleteConfirmation(kind, item) {
  openConfirmation({
    title: kind === "category" ? "删除分类" : "删除标签",
    message: kind === "category"
      ? "删除分类后，相关密码记录将变为未分类。此操作无法撤销。"
      : "删除标签后，相关密码记录上的标签关联将被移除。此操作无法撤销。",
    command: kind === "category" ? categoryDeleteCommand(item) : tagDeleteCommand(item),
    successMessage: kind === "category" ? "分类已删除" : "标签已删除",
  });
}

function openConfirmation(confirmation) {
  if (confirmationOperation !== null || elements.confirmDialog.open) return;
  pendingConfirmation = confirmation;
  elements.confirmTitle.textContent = confirmation.title;
  elements.confirmMessage.textContent = confirmation.message;
  setStatus(elements.confirmStatus);
  elements.confirmDialog.showModal();
  elements.confirmButton.focus();
}

async function runConfirmation() {
  if (pendingConfirmation === null || confirmationOperation !== null) return;
  const confirmation = pendingConfirmation;
  const token = beginOperation("confirmation");
  if (token === null) return;
  setConfirmationPending(true);
  try {
    const nextSnapshot = await client.mutate(confirmation.command);
    if (!isOperationCurrent("confirmation", token)) return;
    applySnapshot(nextSnapshot);
    pendingConfirmation = null;
    elements.confirmDialog.close();
    showToast(confirmation.successMessage);
  } catch (error) {
    if (!isOperationCurrent("confirmation", token)) return;
    await handleOperationError(error, {
      statusNode: elements.confirmStatus,
      closeStaleDialog: elements.confirmDialog,
      scope: "confirmation",
      token,
    });
  } finally {
    if (finishOperation("confirmation", token)) setConfirmationPending(false);
  }
}

async function refreshSnapshot({ announce = false } = {}) {
  if (refreshOperation !== null) return;
  const token = beginOperation("refresh");
  if (token === null) return;
  elements.loadingState.hidden = false;
  elements.credentialList.hidden = true;
  elements.emptyState.hidden = true;
  setButtonBusy(elements.refreshButton, true, "刷新中…", "刷新");
  try {
    const nextSnapshot = await client.refreshSnapshot();
    if (!isOperationCurrent("refresh", token)) return;
    applySnapshot(nextSnapshot);
    if (announce) showToast("密码库已刷新");
  } catch (error) {
    if (!isOperationCurrent("refresh", token)) return;
    await handleOperationError(error, { scope: "refresh", token });
  } finally {
    if (finishOperation("refresh", token)) {
      elements.loadingState.hidden = true;
      setButtonBusy(elements.refreshButton, false, "刷新中…", "刷新");
    }
  }
}

async function refreshAfterStale(code, scope, token) {
  try {
    const nextSnapshot = await client.refreshSnapshot();
    if (!isOperationCurrent(scope, token)) return;
    applySnapshot(nextSnapshot);
    showToast(code === "STALE_VERSION" ? STALE_MESSAGE : NOT_FOUND_MESSAGE);
  } catch (error) {
    if (!isOperationCurrent(scope, token)) return;
    if (error instanceof LanApiError && (error.disconnect || error.code === "DISCONNECTED")) {
      enterDisconnectedState();
      return;
    }
    showToast(error instanceof LanApiError ? error.message : GENERIC_MESSAGE);
  }
}

async function handleOperationError(error, {
  statusNode = null,
  closeStaleDialog = null,
  scope = null,
  token = null,
} = {}) {
  if (scope !== null && !isOperationCurrent(scope, token)) return;
  if (error instanceof LanApiError && error.code === "VALIDATION") {
    setStatus(statusNode ?? elements.taxonomyStatus, error.message);
    return;
  }
  if (error instanceof LanApiError && (error.code === "NOT_FOUND" || error.code === "STALE_VERSION")) {
    if (closeStaleDialog?.open) closeStaleDialog.close();
    await refreshAfterStale(error.code, scope, token);
    return;
  }
  if (error instanceof LanApiError && (error.disconnect || error.code === "DISCONNECTED")) {
    enterDisconnectedState();
    return;
  }
  const message = error instanceof LanApiError ? error.message : GENERIC_MESSAGE;
  if (statusNode !== null) setStatus(statusNode, message);
  else showToast(message);
}

function closeDialog(dialog) {
  if (dialog.open) dialog.close();
}

function clearSensitiveUi() {
  invalidateUiOperations();
  snapshot = emptySnapshot();
  revealedIds.clear();
  filterState = { categoryId: ALL_CATEGORIES, tagId: null, query: "" };
  editingCredentialId = null;
  pendingConfirmation = null;
  pairingInProgress = false;
  setCredentialPending(false);
  setConfirmationPending(false);
  setTaxonomyPending(false);
  setButtonBusy(elements.connectButton, false, "连接中…", "连接手机");
  setButtonBusy(elements.refreshButton, false, "刷新中…", "刷新");
  elements.loadingState.hidden = true;
  elements.accessCode.value = "";
  elements.searchInput.value = "";
  elements.currentFilter.textContent = "全部密码";
  elements.credentialList.replaceChildren();
  elements.filterNavigation.replaceChildren();
  elements.categoryList.replaceChildren();
  elements.tagList.replaceChildren();
  elements.newCategoryName.value = "";
  elements.newTagName.value = "";
  elements.confirmTitle.textContent = "确认操作";
  elements.confirmMessage.textContent = "";
  elements.credentialDialogTitle.textContent = "新增密码";
  setStatus(elements.confirmStatus);
  setStatus(elements.taxonomyStatus);
  clearCredentialForm();
  for (const dialog of document.querySelectorAll("dialog")) closeDialog(dialog);
  if (toastTimer !== null) clearTimeout(toastTimer);
  toastTimer = null;
  elements.toastRegion.textContent = "";
  elements.toastRegion.hidden = true;
}

function enterDisconnectedState() {
  clearSensitiveUi();
  elements.pairingView.hidden = true;
  elements.vaultView.hidden = false;
  elements.vaultContent.hidden = true;
  elements.disconnectBanner.hidden = false;
  elements.disconnectBanner.querySelector("p").textContent = DISCONNECTED_MESSAGE;
}

async function submitPairing(event) {
  event.preventDefault();
  if (pairingInProgress || pairingOperation !== null) return;
  let accessCode = elements.accessCode.value;
  elements.accessCode.value = "";
  if (!/^[0-9]{6}$/.test(accessCode)) {
    accessCode = "";
    setStatus(elements.pairingStatus, "访问码必须为六位数字");
    elements.accessCode.focus();
    return;
  }
  const token = beginOperation("pairing");
  if (token === null) return;
  pairingInProgress = true;
  setButtonBusy(elements.connectButton, true, "连接中…", "连接手机");
  setStatus(elements.pairingStatus, "正在建立安全连接…");
  try {
    const pairing = client.pair(accessCode);
    accessCode = "";
    const nextSnapshot = await pairing;
    if (!isOperationCurrent("pairing", token)) return;
    applySnapshot(nextSnapshot);
    elements.pairingView.hidden = true;
    elements.vaultView.hidden = false;
    elements.vaultContent.hidden = false;
    elements.disconnectBanner.hidden = true;
  } catch (error) {
    accessCode = "";
    if (!isOperationCurrent("pairing", token)) return;
    if (error instanceof LanApiError && error.code === "UNAUTHORIZED") {
      setStatus(elements.pairingStatus, "访问码错误或已失效");
    } else if (error instanceof LanApiError && error.disconnect) {
      enterDisconnectedState();
    } else {
      setStatus(elements.pairingStatus, error instanceof LanApiError ? error.message : GENERIC_MESSAGE);
    }
  } finally {
    if (finishOperation("pairing", token)) {
      pairingInProgress = false;
      setButtonBusy(elements.connectButton, false, "连接中…", "连接手机");
    }
  }
}

elements.accessCode.addEventListener("input", () => {
  elements.accessCode.value = elements.accessCode.value.replace(/[^0-9]/g, "").slice(0, 6);
});
elements.pairingForm.addEventListener("submit", submitPairing);
elements.searchInput.addEventListener("input", () => {
  filterState.query = elements.searchInput.value;
  renderCredentials();
});
elements.refreshButton.addEventListener("click", () => refreshSnapshot({ announce: true }));
elements.addCredentialButton.addEventListener("click", () => openCredentialDialog());
elements.manageTaxonomyButton.addEventListener("click", openTaxonomyDialog);
elements.credentialForm.addEventListener("submit", submitCredential);
elements.credentialCancelButton.addEventListener("click", () => {
  if (credentialOperation === null) elements.credentialDialog.close();
});
elements.credentialCloseButton.addEventListener("click", () => {
  if (credentialOperation === null) elements.credentialDialog.close();
});
elements.credentialDialog.addEventListener("cancel", (event) => {
  if (credentialOperation !== null) event.preventDefault();
});
elements.credentialDialog.addEventListener("close", clearCredentialForm);
elements.taxonomyCloseButton.addEventListener("click", () => {
  if (taxonomyOperation === null) elements.taxonomyDialog.close();
});
elements.taxonomyDialog.addEventListener("cancel", (event) => {
  if (taxonomyOperation !== null) event.preventDefault();
});
elements.taxonomyDialog.addEventListener("close", () => {
  elements.newCategoryName.value = "";
  elements.newTagName.value = "";
  setStatus(elements.taxonomyStatus);
});
elements.categoryCreateForm.addEventListener("submit", (event) => {
  event.preventDefault();
  createTaxonomy("category", elements.newCategoryName);
});
elements.tagCreateForm.addEventListener("submit", (event) => {
  event.preventDefault();
  createTaxonomy("tag", elements.newTagName);
});
elements.confirmButton.addEventListener("click", runConfirmation);
elements.confirmCancelButton.addEventListener("click", () => {
  if (confirmationOperation === null) elements.confirmDialog.close();
});
elements.confirmDialog.addEventListener("cancel", (event) => {
  if (confirmationOperation !== null) event.preventDefault();
});
elements.confirmDialog.addEventListener("close", () => {
  pendingConfirmation = null;
  elements.confirmMessage.textContent = "";
  setStatus(elements.confirmStatus);
});
globalThis.addEventListener("pagehide", () => {
  client.disconnect("PAGEHIDE");
  clearSensitiveUi();
}, { once: true });
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible" && client.status === "connected") {
    client.checkHealth().catch(() => {});
  }
});
