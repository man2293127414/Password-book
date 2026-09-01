package com.passwordvault.local;

import android.app.Activity;
import android.app.AlertDialog;
import android.Manifest;
import android.content.pm.PackageManager;
import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Intent;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PersistableBundle;
import android.text.Editable;
import android.text.InputType;
import android.text.TextWatcher;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.view.inputmethod.EditorInfo;
import android.widget.ArrayAdapter;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import com.passwordvault.local.backup.AndroidBackupFiles;
import com.passwordvault.local.core.backup.BackupCrypto;
import com.passwordvault.local.core.backup.BackupException;
import com.passwordvault.local.core.backup.BackupService;
import com.passwordvault.local.core.backup.CorruptBackupException;
import com.passwordvault.local.core.backup.ImportPreview;
import com.passwordvault.local.core.backup.UnsupportedBackupVersionException;
import com.passwordvault.local.core.backup.WrongBackupPasswordException;
import com.passwordvault.local.core.codec.VaultBinaryCodec;
import com.passwordvault.local.core.crypto.CryptoException;
import com.passwordvault.local.core.lan.LanSessionManager;
import com.passwordvault.local.core.lan.LanSessionState;
import com.passwordvault.local.core.model.Category;
import com.passwordvault.local.core.model.Credential;
import com.passwordvault.local.core.model.CredentialDraft;
import com.passwordvault.local.core.model.Tag;
import com.passwordvault.local.core.model.VaultSnapshot;
import com.passwordvault.local.core.query.VaultFilter;
import com.passwordvault.local.core.query.VaultQuery;
import com.passwordvault.local.core.repository.ConflictException;
import com.passwordvault.local.core.repository.NotFoundException;
import com.passwordvault.local.core.repository.VaultService;
import com.passwordvault.local.core.validation.ValidationException;
import com.passwordvault.local.lan.LanAccessService;
import com.passwordvault.local.ui.BackupController;
import com.passwordvault.local.ui.CredentialEditorController;
import com.passwordvault.local.ui.TaxonomyController;
import com.passwordvault.local.ui.VaultListController;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;

public final class MainActivity extends Activity {
    private enum Screen {
        PASSWORDS,
        DETAIL,
        EDITOR,
        TAXONOMY,
        MORE
    }

    private static final int ACTION_PRIMARY = 1;
    private static final int ACTION_SECONDARY = 2;
    private static final int ACTION_DANGER = 3;
    static final int REQUEST_EXPORT_BACKUP = 201;
    static final int REQUEST_IMPORT_BACKUP = 202;
    static final int REQUEST_LAN_PERMISSIONS = 203;

    private VaultListController listController;
    private CredentialEditorController editorController;
    private TaxonomyController taxonomyController;
    private BackupController backupController;
    private LanSessionManager lanSessionManager;
    private AndroidBackupFiles backupFiles;
    private ExecutorService backupExecutor;
    private ImportPreview activeImportPreview;
    private AlertDialog activeBackupDialog;
    private volatile boolean destroyed;

    private FrameLayout contentContainer;
    private TextView navPasswords;
    private TextView navTaxonomy;
    private TextView navMore;
    private LinearLayout credentialListContainer;
    private TextView credentialCountView;
    private EditText editorPasswordInput;
    private boolean editorPasswordVisible;
    private TextView lanStatusView;
    private TextView lanToggleView;
    private final Handler lanStatusHandler = new Handler(Looper.getMainLooper());
    private final Runnable lanStatusRefresh = new Runnable() { @Override public void run() { if (!destroyed && screen == Screen.MORE) { updateLanAccessCard(); lanStatusHandler.postDelayed(this, 750L); } } };

    private Screen screen = Screen.PASSWORDS;
    private String selectedCredentialId;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        setContentView(R.layout.activity_main);

        contentContainer = findViewById(R.id.content_container);
        navPasswords = findViewById(R.id.nav_passwords);
        navTaxonomy = findViewById(R.id.nav_taxonomy);
        navMore = findViewById(R.id.nav_more);

        navPasswords.setOnClickListener(view -> showPasswords());
        navTaxonomy.setOnClickListener(view -> showTaxonomy());
        navMore.setOnClickListener(view -> showMore());

        PasswordVaultApplication app = (PasswordVaultApplication) getApplication();
        VaultService service = app.getVaultService();
        listController = new VaultListController(service, new VaultQuery());
        editorController = new CredentialEditorController(service);
        taxonomyController = new TaxonomyController(service);
        lanSessionManager = ((PasswordVaultApplication) getApplication()).getLanSessionManager();
        backupController = new BackupController(
                service,
                new BackupService(service, new VaultBinaryCodec(), new BackupCrypto(new SecureRandom())),
                new Runnable() {
                    @Override
                    public void run() {
                        ((PasswordVaultApplication) getApplication()).stopLanAccess();
                    }
                }
        );
        backupFiles = new AndroidBackupFiles(this);
        backupExecutor = Executors.newSingleThreadExecutor();
        showPasswords();
    }

    @Override
    protected void onPause() {
        lanStatusHandler.removeCallbacks(lanStatusRefresh);
        if (listController != null) {
            listController.concealPasswords();
        }
        concealEditorPassword();
        if (screen == Screen.PASSWORDS && credentialListContainer != null) {
            refreshCredentialList();
        } else if (screen == Screen.DETAIL) {
            renderDetail();
        }
        super.onPause();
    }

    @Override protected void onResume() {
        super.onResume();
        if (screen == Screen.MORE) { updateLanAccessCard(); lanStatusHandler.postDelayed(lanStatusRefresh, 750L); }
    }

    @Override
    protected void onStop() {
        if (listController != null) {
            listController.onStop();
        }
        super.onStop();
    }

    @Override
    protected void onDestroy() {
        lanStatusHandler.removeCallbacks(lanStatusRefresh);
        destroyed = true;
        cancelActiveImportPreview();
        closeVaultAfterBackupWork();
        super.onDestroy();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK || data == null || data.getData() == null) {
            return;
        }
        if (requestCode == REQUEST_EXPORT_BACKUP) {
            showBackupPasswordDialog(data.getData(), true);
        } else if (requestCode == REQUEST_IMPORT_BACKUP) {
            showBackupPasswordDialog(data.getData(), false);
        }
    }

    @Override
    public void onBackPressed() {
        if (screen == Screen.DETAIL) {
            showPasswords();
        } else if (screen == Screen.EDITOR) {
            if (selectedCredentialId == null) {
                showPasswords();
            } else {
                renderDetailScreen(selectedCredentialId);
            }
        } else if (screen == Screen.TAXONOMY || screen == Screen.MORE) {
            showPasswords();
        } else {
            super.onBackPressed();
        }
    }

    private void showPasswords() {
        screen = Screen.PASSWORDS;
        selectedCredentialId = null;
        editorPasswordInput = null;
        editorPasswordVisible = false;
        listController.concealPasswords();
        renderPasswordScreen();
    }

    private void renderPasswordScreen() {
        try {
            LinearLayout page = verticalPage();

            LinearLayout header = horizontalRow();
            LinearLayout titleBlock = new LinearLayout(this);
            titleBlock.setOrientation(LinearLayout.VERTICAL);
            titleBlock.addView(text("密码记录器", 24, color(R.color.text_primary), true));
            credentialCountView = text("", 13, color(R.color.text_secondary), false);
            titleBlock.addView(credentialCountView);
            header.addView(titleBlock, weightedParams());

            TextView add = action("添加", ACTION_PRIMARY);
            add.setId(R.id.add_credential);
            add.setOnClickListener(view -> showEditor(null));
            header.addView(add);
            page.addView(header, matchWrapParams(0));

            EditText search = input(getString(R.string.search_hint), listController.getSearchText());
            search.setId(R.id.search_input);
            search.setSingleLine(true);
            search.setInputType(InputType.TYPE_CLASS_TEXT);
            search.addTextChangedListener(new TextWatcher() {
                @Override
                public void beforeTextChanged(CharSequence value, int start, int count, int after) {
                }

                @Override
                public void onTextChanged(CharSequence value, int start, int before, int count) {
                    listController.setSearchText(value == null ? "" : value.toString());
                    refreshCredentialList();
                }

                @Override
                public void afterTextChanged(Editable value) {
                }
            });
            page.addView(search, matchWrapParams(16));

            VaultSnapshot snapshot = listController.snapshot();
            HorizontalScrollView categoryScroll = new HorizontalScrollView(this);
            categoryScroll.setHorizontalScrollBarEnabled(false);
            LinearLayout categoryRow = horizontalRow();
            categoryRow.addView(categoryChip("全部", null));
            categoryRow.addView(categoryChip(
                    "未分类",
                    VaultFilter.UNCLASSIFIED_CATEGORY_ID
            ), marginStartParams(8));
            for (Category category : snapshot.getCategories()) {
                categoryRow.addView(categoryChip(category.getName(), category.getId()), marginStartParams(8));
            }
            categoryScroll.addView(categoryRow);
            page.addView(categoryScroll, matchWrapParams(12));

            String tagFilterText = listController.getTagIds().isEmpty()
                    ? "标签筛选"
                    : "标签筛选 · " + listController.getTagIds().size() + " 个";
            TextView tagFilter = action(tagFilterText, ACTION_SECONDARY);
            tagFilter.setOnClickListener(view -> showTagFilterDialog());
            page.addView(tagFilter, matchWrapParams(10));

            ScrollView listScroll = new ScrollView(this);
            listScroll.setFillViewport(true);
            credentialListContainer = new LinearLayout(this);
            credentialListContainer.setId(R.id.credential_list);
            credentialListContainer.setOrientation(LinearLayout.VERTICAL);
            credentialListContainer.setPadding(0, dp(2), 0, dp(20));
            listScroll.addView(credentialListContainer);
            page.addView(listScroll, weightedHeightParams(12));

            setContent(page);
            updateNavigation();
            refreshCredentialList();
        } catch (RuntimeException exception) {
            showLoadFailure(exception);
        }
    }

    private TextView categoryChip(String label, String categoryId) {
        boolean selected = categoryId == null
                ? listController.getCategoryId() == null
                : categoryId.equals(listController.getCategoryId());
        TextView chip = text(label, 14, selected ? color(R.color.primary) : color(R.color.text_secondary), selected);
        chip.setGravity(Gravity.CENTER);
        chip.setPadding(dp(14), dp(8), dp(14), dp(8));
        chip.setBackgroundResource(selected ? R.drawable.bg_chip_selected : R.drawable.bg_chip);
        chip.setClickable(true);
        chip.setFocusable(true);
        chip.setOnClickListener(view -> {
            listController.setCategoryId(categoryId);
            renderPasswordScreen();
        });
        return chip;
    }

    private void showTagFilterDialog() {
        VaultSnapshot snapshot;
        try {
            snapshot = listController.snapshot();
        } catch (RuntimeException exception) {
            showOperationError(exception);
            return;
        }
        List<Tag> tags = snapshot.getTags();
        if (tags.isEmpty()) {
            Toast.makeText(this, "还没有标签，可在“分类标签”中创建", Toast.LENGTH_SHORT).show();
            return;
        }

        String[] names = new String[tags.size()];
        boolean[] checked = new boolean[tags.size()];
        for (int index = 0; index < tags.size(); index++) {
            names[index] = tags.get(index).getName();
            checked[index] = listController.getTagIds().contains(tags.get(index).getId());
        }

        new AlertDialog.Builder(this)
                .setTitle("选择标签")
                .setMultiChoiceItems(names, checked, (dialog, which, isChecked) -> checked[which] = isChecked)
                .setNegativeButton("取消", null)
                .setNeutralButton("清空", (dialog, which) -> {
                    listController.setTagIds(Collections.<String>emptySet());
                    renderPasswordScreen();
                })
                .setPositiveButton("完成", (dialog, which) -> {
                    Set<String> selected = new LinkedHashSet<String>();
                    for (int index = 0; index < tags.size(); index++) {
                        if (checked[index]) {
                            selected.add(tags.get(index).getId());
                        }
                    }
                    listController.setTagIds(selected);
                    renderPasswordScreen();
                })
                .show();
    }

    private void refreshCredentialList() {
        if (credentialListContainer == null) {
            return;
        }
        try {
            VaultSnapshot snapshot = listController.snapshot();
            List<Credential> credentials = listController.visibleCredentials();
            credentialCountView.setText(String.format(
                    Locale.CHINA,
                    "显示 %d / %d 条记录",
                    credentials.size(),
                    snapshot.getCredentials().size()
            ));
            credentialListContainer.removeAllViews();
            if (credentials.isEmpty()) {
                LinearLayout empty = card();
                empty.addView(text(
                        snapshot.getCredentials().isEmpty() ? "还没有密码记录" : "没有匹配的记录",
                        17,
                        color(R.color.text_primary),
                        true
                ));
                empty.addView(text(
                        snapshot.getCredentials().isEmpty() ? "点击右上角“添加”开始记录。" : "请调整搜索或筛选条件。",
                        14,
                        color(R.color.text_secondary),
                        false
                ), matchWrapParams(8));
                credentialListContainer.addView(empty, matchWrapParams(12));
                return;
            }

            for (Credential credential : credentials) {
                credentialListContainer.addView(
                        credentialCard(credential, snapshot),
                        matchWrapParams(10)
                );
            }
        } catch (RuntimeException exception) {
            credentialListContainer.removeAllViews();
            credentialListContainer.addView(errorCard(userMessage(exception)));
        }
    }

    private View credentialCard(Credential credential, VaultSnapshot snapshot) {
        LinearLayout card = card();
        card.setTag("credential:" + credential.getId());
        card.setClickable(true);
        card.setFocusable(true);
        card.setOnClickListener(view -> showDetail(credential.getId()));

        card.addView(text(credential.getName(), 18, color(R.color.text_primary), true));
        String account = isBlank(credential.getAccount()) ? "未填写账号" : credential.getAccount();
        card.addView(text(account, 14, color(R.color.text_secondary), false), matchWrapParams(4));

        String taxonomy = taxonomySummary(credential, snapshot);
        if (!taxonomy.isEmpty()) {
            card.addView(text(taxonomy, 13, color(R.color.text_secondary), false), matchWrapParams(8));
        }

        LinearLayout passwordRow = horizontalRow();
        TextView password = text(
                listController.passwordText(credential),
                17,
                color(R.color.text_primary),
                false
        );
        password.setTypeface(Typeface.MONOSPACE);
        password.setContentDescription(listController.isPasswordRevealed(credential.getId())
                ? "密码已显示"
                : "密码已隐藏");
        passwordRow.addView(password, weightedParams());
        TextView reveal = action(
                listController.isPasswordRevealed(credential.getId()) ? "隐藏" : "显示",
                ACTION_SECONDARY
        );
        reveal.setOnClickListener(view -> {
            listController.togglePassword(credential.getId());
            refreshCredentialList();
        });
        passwordRow.addView(reveal);
        card.addView(passwordRow, matchWrapParams(12));

        LinearLayout actions = horizontalRow();
        TextView copyAccount = action("复制账号", ACTION_SECONDARY);
        if (isBlank(credential.getAccount())) {
            copyAccount.setEnabled(false);
            copyAccount.setAlpha(0.45f);
        } else {
            copyAccount.setOnClickListener(view -> copyText("账号", credential.getAccount(), false));
        }
        actions.addView(copyAccount, weightedActionParams(0));

        TextView copyPassword = action("复制密码", ACTION_SECONDARY);
        copyPassword.setOnClickListener(view -> copyText("密码", credential.getPassword(), true));
        actions.addView(copyPassword, weightedActionParams(8));

        TextView details = action("详情", ACTION_PRIMARY);
        details.setOnClickListener(view -> showDetail(credential.getId()));
        actions.addView(details, weightedActionParams(8));
        card.addView(actions, matchWrapParams(12));
        return card;
    }

    private void showDetail(String credentialId) {
        listController.concealPasswords();
        renderDetailScreen(credentialId);
    }

    private void renderDetailScreen(String credentialId) {
        selectedCredentialId = credentialId;
        screen = Screen.DETAIL;
        editorPasswordInput = null;
        editorPasswordVisible = false;
        renderDetail();
    }

    private void renderDetail() {
        try {
            Credential credential = listController.findCredential(selectedCredentialId);
            VaultSnapshot snapshot = listController.snapshot();

            ScrollView scroll = new ScrollView(this);
            LinearLayout page = verticalPage();
            scroll.addView(page);

            LinearLayout header = horizontalRow();
            TextView back = action("返回", ACTION_SECONDARY);
            back.setOnClickListener(view -> showPasswords());
            header.addView(back);
            TextView title = text(credential.getName(), 22, color(R.color.text_primary), true);
            title.setGravity(Gravity.CENTER_VERTICAL);
            header.addView(title, weightedMarginParams(12));
            TextView edit = action("编辑", ACTION_PRIMARY);
            edit.setOnClickListener(view -> showEditor(credential.getId()));
            header.addView(edit);
            page.addView(header);

            LinearLayout details = card();
            addDetailField(details, "账号", fallback(credential.getAccount()));

            TextView passwordLabel = text("密码", 12, color(R.color.text_secondary), false);
            details.addView(passwordLabel, matchWrapParams(14));
            LinearLayout passwordRow = horizontalRow();
            TextView password = text(
                    listController.passwordText(credential),
                    17,
                    color(R.color.text_primary),
                    false
            );
            password.setTypeface(Typeface.MONOSPACE);
            passwordRow.addView(password, weightedParams());
            TextView reveal = action(
                    listController.isPasswordRevealed(credential.getId()) ? "隐藏" : "显示",
                    ACTION_SECONDARY
            );
            reveal.setOnClickListener(view -> {
                listController.togglePassword(credential.getId());
                renderDetail();
            });
            passwordRow.addView(reveal);
            details.addView(passwordRow, matchWrapParams(4));

            addDetailField(details, "网址", fallback(credential.getUrl()));
            addDetailField(details, "分类与标签", fallback(taxonomySummary(credential, snapshot)));
            addDetailField(details, "备注", fallback(credential.getNotes()));
            page.addView(details, matchWrapParams(16));

            LinearLayout copyActions = horizontalRow();
            TextView copyAccount = action("复制账号", ACTION_SECONDARY);
            copyAccount.setEnabled(!isBlank(credential.getAccount()));
            copyAccount.setAlpha(copyAccount.isEnabled() ? 1f : 0.45f);
            copyAccount.setOnClickListener(view -> copyText("账号", credential.getAccount(), false));
            copyActions.addView(copyAccount, weightedActionParams(0));
            TextView copyPassword = action("复制密码", ACTION_PRIMARY);
            copyPassword.setOnClickListener(view -> copyText("密码", credential.getPassword(), true));
            copyActions.addView(copyPassword, weightedActionParams(8));
            page.addView(copyActions, matchWrapParams(12));

            TextView delete = action("永久删除这条记录", ACTION_DANGER);
            delete.setOnClickListener(view -> confirmDeleteCredential(credential));
            page.addView(delete, matchWrapParams(20));

            setContent(scroll);
            updateNavigation();
        } catch (NotFoundException exception) {
            showPasswords();
        } catch (RuntimeException exception) {
            showLoadFailure(exception);
        }
    }

    private void confirmDeleteCredential(Credential credential) {
        new AlertDialog.Builder(this)
                .setTitle("删除密码记录？")
                .setMessage("“" + credential.getName() + "”将被永久删除，无法撤销。")
                .setNegativeButton("取消", null)
                .setPositiveButton("删除", (dialog, which) -> {
                    try {
                        listController.deleteCredential(credential.getId(), credential.getVersion());
                        Toast.makeText(this, "已删除", Toast.LENGTH_SHORT).show();
                        showPasswords();
                    } catch (RuntimeException exception) {
                        showOperationError(exception);
                    }
                })
                .show();
    }

    private void showEditor(String credentialId) {
        listController.concealPasswords();
        selectedCredentialId = credentialId;
        screen = Screen.EDITOR;
        editorPasswordVisible = false;
        renderEditor();
    }

    private void renderEditor() {
        try {
            VaultSnapshot snapshot = listController.snapshot();
            Credential existing = selectedCredentialId == null
                    ? null
                    : listController.findCredential(selectedCredentialId);

            ScrollView scroll = new ScrollView(this);
            LinearLayout page = verticalPage();
            scroll.addView(page);

            LinearLayout header = horizontalRow();
            View.OnClickListener cancelEditor = view -> {
                if (existing == null) {
                    showPasswords();
                } else {
                    renderDetailScreen(existing.getId());
                }
            };
            TextView cancel = action("取消", ACTION_SECONDARY);
            cancel.setOnClickListener(cancelEditor);
            header.addView(cancel);
            TextView title = text(
                    existing == null ? "新增密码" : "编辑密码",
                    22,
                    color(R.color.text_primary),
                    true
            );
            title.setGravity(Gravity.CENTER);
            header.addView(title, weightedMarginParams(12));
            page.addView(header);

            LinearLayout form = card();
            form.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
            EditText nameInput = labeledInput(
                    form, "名称 *", "例如：GitHub", existing == null ? "" : existing.getName(),
                    InputType.TYPE_CLASS_TEXT, false
            );
            EditText accountInput = labeledInput(
                    form, "账号", "用户名、邮箱或手机号", existing == null ? "" : existing.getAccount(),
                    InputType.TYPE_CLASS_TEXT, false
            );
            editorPasswordInput = labeledInput(
                    form, "密码 *", "输入密码", existing == null ? "" : existing.getPassword(),
                    InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD, false
            );
            editorPasswordInput.setTransformationMethod(PasswordTransformationMethod.getInstance());
            editorPasswordInput.setImeOptions(EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING);
            editorPasswordInput.setSaveEnabled(false);
            TextView revealPassword = action("显示或隐藏密码", ACTION_SECONDARY);
            revealPassword.setOnClickListener(view -> {
                editorPasswordVisible = !editorPasswordVisible;
                applyEditorPasswordVisibility();
            });
            form.addView(revealPassword, matchWrapParams(8));
            EditText urlInput = labeledInput(
                    form, "网址", "https://example.com", existing == null ? "" : existing.getUrl(),
                    InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI, false
            );

            form.addView(text("分类", 13, color(R.color.text_secondary), false), matchWrapParams(14));
            List<Category> categories = snapshot.getCategories();
            List<String> categoryNames = new ArrayList<String>();
            categoryNames.add("未分类");
            int selectedCategoryIndex = 0;
            for (int index = 0; index < categories.size(); index++) {
                Category category = categories.get(index);
                categoryNames.add(category.getName());
                if (existing != null && category.getId().equals(existing.getCategoryId())) {
                    selectedCategoryIndex = index + 1;
                }
            }
            Spinner categoryInput = new Spinner(this);
            categoryInput.setBackgroundResource(R.drawable.bg_input);
            categoryInput.setPadding(dp(8), dp(2), dp(8), dp(2));
            ArrayAdapter<String> categoryAdapter = new ArrayAdapter<String>(
                    this,
                    android.R.layout.simple_spinner_dropdown_item,
                    categoryNames
            );
            categoryInput.setAdapter(categoryAdapter);
            categoryInput.setSelection(selectedCategoryIndex);
            form.addView(categoryInput, matchWrapParams(4));

            form.addView(text("标签", 13, color(R.color.text_secondary), false), matchWrapParams(14));
            Map<String, CheckBox> tagInputs = new LinkedHashMap<String, CheckBox>();
            if (snapshot.getTags().isEmpty()) {
                form.addView(text("暂无标签，可在“分类标签”页创建。", 14, color(R.color.text_secondary), false));
            } else {
                for (Tag tag : snapshot.getTags()) {
                    CheckBox checkBox = new CheckBox(this);
                    checkBox.setText(tag.getName());
                    checkBox.setTextColor(color(R.color.text_primary));
                    checkBox.setChecked(existing != null && existing.getTagIds().contains(tag.getId()));
                    tagInputs.put(tag.getId(), checkBox);
                    form.addView(checkBox);
                }
            }

            EditText notesInput = labeledInput(
                    form, "备注", "可选", existing == null ? "" : existing.getNotes(),
                    InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE, true
            );
            page.addView(form, matchWrapParams(16));

            LinearLayout actions = horizontalRow();
            TextView cancelBottom = action("取消", ACTION_SECONDARY);
            cancelBottom.setOnClickListener(cancelEditor);
            actions.addView(cancelBottom, weightedActionParams(0));
            TextView save = action("保存", ACTION_PRIMARY);
            save.setOnClickListener(view -> {
                String categoryId = categoryInput.getSelectedItemPosition() == 0
                        ? null
                        : categories.get(categoryInput.getSelectedItemPosition() - 1).getId();
                Set<String> selectedTagIds = new LinkedHashSet<String>();
                for (Map.Entry<String, CheckBox> entry : tagInputs.entrySet()) {
                    if (entry.getValue().isChecked()) {
                        selectedTagIds.add(entry.getKey());
                    }
                }
                CredentialDraft draft = new CredentialDraft(
                        nameInput.getText().toString(),
                        accountInput.getText().toString(),
                        editorPasswordInput.getText().toString(),
                        urlInput.getText().toString(),
                        categoryId,
                        selectedTagIds,
                        notesInput.getText().toString()
                );
                try {
                    Credential saved = existing == null
                            ? editorController.create(draft)
                            : editorController.update(existing, draft);
                    Toast.makeText(this, "已保存", Toast.LENGTH_SHORT).show();
                    listController.concealPasswords();
                    renderDetailScreen(saved.getId());
                } catch (ValidationException exception) {
                    if (exception.getMessage().contains("名称")) {
                        nameInput.setError(exception.getMessage());
                        nameInput.requestFocus();
                    } else if (exception.getMessage().contains("密码")) {
                        editorPasswordInput.setError(exception.getMessage());
                        editorPasswordInput.requestFocus();
                    } else {
                        showOperationError(exception);
                    }
                } catch (RuntimeException exception) {
                    showOperationError(exception);
                }
            });
            actions.addView(save, weightedActionParams(8));
            page.addView(actions, matchWrapParams(12));

            setContent(scroll);
            updateNavigation();
        } catch (NotFoundException exception) {
            showPasswords();
        } catch (RuntimeException exception) {
            showLoadFailure(exception);
        }
    }

    private void applyEditorPasswordVisibility() {
        if (editorPasswordInput == null) {
            return;
        }
        int selection = editorPasswordInput.getSelectionStart();
        editorPasswordInput.setTransformationMethod(editorPasswordVisible
                ? HideReturnsTransformationMethod.getInstance()
                : PasswordTransformationMethod.getInstance());
        if (selection >= 0 && selection <= editorPasswordInput.length()) {
            editorPasswordInput.setSelection(selection);
        }
    }

    private void concealEditorPassword() {
        if (editorPasswordInput != null && editorPasswordVisible) {
            editorPasswordVisible = false;
            applyEditorPasswordVisibility();
        }
    }

    private void showTaxonomy() {
        listController.concealPasswords();
        selectedCredentialId = null;
        editorPasswordInput = null;
        screen = Screen.TAXONOMY;
        renderTaxonomy();
    }

    private void renderTaxonomy() {
        try {
            VaultSnapshot snapshot = taxonomyController.snapshot();
            ScrollView scroll = new ScrollView(this);
            LinearLayout page = verticalPage();
            scroll.addView(page);

            page.addView(text("分类与标签", 24, color(R.color.text_primary), true));
            page.addView(text("删除分类或标签不会删除密码记录。", 14, color(R.color.text_secondary), false), matchWrapParams(5));

            LinearLayout categoryHeader = horizontalRow();
            categoryHeader.addView(text("分类", 19, color(R.color.text_primary), true), weightedParams());
            TextView addCategory = action("新增分类", ACTION_PRIMARY);
            addCategory.setOnClickListener(view -> showTaxonomyNameDialog(
                    "新增分类", "", value -> taxonomyController.createCategory(value)
            ));
            categoryHeader.addView(addCategory);
            page.addView(categoryHeader, matchWrapParams(22));
            if (snapshot.getCategories().isEmpty()) {
                page.addView(emptyTaxonomyCard("还没有分类"), matchWrapParams(10));
            } else {
                for (Category category : snapshot.getCategories()) {
                    page.addView(categoryCard(category, snapshot), matchWrapParams(10));
                }
            }

            LinearLayout tagHeader = horizontalRow();
            tagHeader.addView(text("标签", 19, color(R.color.text_primary), true), weightedParams());
            TextView addTag = action("新增标签", ACTION_PRIMARY);
            addTag.setOnClickListener(view -> showTaxonomyNameDialog(
                    "新增标签", "", value -> taxonomyController.createTag(value)
            ));
            tagHeader.addView(addTag);
            page.addView(tagHeader, matchWrapParams(24));
            if (snapshot.getTags().isEmpty()) {
                page.addView(emptyTaxonomyCard("还没有标签"), matchWrapParams(10));
            } else {
                for (Tag tag : snapshot.getTags()) {
                    page.addView(tagCard(tag, snapshot), matchWrapParams(10));
                }
            }

            setContent(scroll);
            updateNavigation();
        } catch (RuntimeException exception) {
            showLoadFailure(exception);
        }
    }

    private View categoryCard(Category category, VaultSnapshot snapshot) {
        LinearLayout card = card();
        LinearLayout row = horizontalRow();
        LinearLayout label = new LinearLayout(this);
        label.setOrientation(LinearLayout.VERTICAL);
        label.addView(text(category.getName(), 16, color(R.color.text_primary), true));
        label.addView(text(
                usageCountByCategory(snapshot, category.getId()) + " 条记录",
                13,
                color(R.color.text_secondary),
                false
        ));
        row.addView(label, weightedParams());
        TextView rename = action("重命名", ACTION_SECONDARY);
        rename.setOnClickListener(view -> showTaxonomyNameDialog(
                "重命名分类",
                category.getName(),
                value -> taxonomyController.renameCategory(category.getId(), category.getVersion(), value)
        ));
        row.addView(rename);
        TextView delete = action("删除", ACTION_DANGER);
        delete.setOnClickListener(view -> confirmDeleteCategory(category));
        row.addView(delete, marginStartParams(8));
        card.addView(row);
        return card;
    }

    private View tagCard(Tag tag, VaultSnapshot snapshot) {
        LinearLayout card = card();
        LinearLayout row = horizontalRow();
        LinearLayout label = new LinearLayout(this);
        label.setOrientation(LinearLayout.VERTICAL);
        label.addView(text(tag.getName(), 16, color(R.color.text_primary), true));
        label.addView(text(
                usageCountByTag(snapshot, tag.getId()) + " 条记录",
                13,
                color(R.color.text_secondary),
                false
        ));
        row.addView(label, weightedParams());
        TextView rename = action("重命名", ACTION_SECONDARY);
        rename.setOnClickListener(view -> showTaxonomyNameDialog(
                "重命名标签",
                tag.getName(),
                value -> taxonomyController.renameTag(tag.getId(), tag.getVersion(), value)
        ));
        row.addView(rename);
        TextView delete = action("删除", ACTION_DANGER);
        delete.setOnClickListener(view -> confirmDeleteTag(tag));
        row.addView(delete, marginStartParams(8));
        card.addView(row);
        return card;
    }

    private void showTaxonomyNameDialog(String title, String initialValue, NameMutation mutation) {
        EditText input = input("输入名称", initialValue);
        input.setSingleLine(true);
        int horizontalPadding = dp(20);
        FrameLayout wrapper = new FrameLayout(this);
        wrapper.setPadding(horizontalPadding, dp(4), horizontalPadding, 0);
        wrapper.addView(input, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(title)
                .setView(wrapper)
                .setNegativeButton("取消", null)
                .setPositiveButton("保存", null)
                .create();
        dialog.setOnShowListener(ignored -> dialog.getButton(AlertDialog.BUTTON_POSITIVE)
                .setOnClickListener(view -> {
                    try {
                        mutation.run(input.getText().toString());
                        dialog.dismiss();
                        renderTaxonomy();
                    } catch (ValidationException exception) {
                        input.setError(exception.getMessage());
                        input.requestFocus();
                    } catch (RuntimeException exception) {
                        showOperationError(exception);
                    }
                }));
        dialog.show();
    }

    private void confirmDeleteCategory(Category category) {
        new AlertDialog.Builder(this)
                .setTitle("删除分类？")
                .setMessage("分类“" + category.getName() + "”将被删除，关联记录会变为未分类。")
                .setNegativeButton("取消", null)
                .setPositiveButton("删除", (dialog, which) -> {
                    try {
                        taxonomyController.deleteCategory(category.getId(), category.getVersion());
                        renderTaxonomy();
                    } catch (RuntimeException exception) {
                        showOperationError(exception);
                    }
                })
                .show();
    }

    private void confirmDeleteTag(Tag tag) {
        new AlertDialog.Builder(this)
                .setTitle("删除标签？")
                .setMessage("标签“" + tag.getName() + "”将从所有记录移除，密码记录不会被删除。")
                .setNegativeButton("取消", null)
                .setPositiveButton("删除", (dialog, which) -> {
                    try {
                        taxonomyController.deleteTag(tag.getId(), tag.getVersion());
                        renderTaxonomy();
                    } catch (RuntimeException exception) {
                        showOperationError(exception);
                    }
                })
                .show();
    }

    private void showMore() {
        listController.concealPasswords();
        selectedCredentialId = null;
        editorPasswordInput = null;
        screen = Screen.MORE;
        renderMore();
    }

    private void renderMore() {
        ScrollView scroll = new ScrollView(this);
        LinearLayout page = verticalPage();
        scroll.addView(page);

        page.addView(text("更多", 24, color(R.color.text_primary), true));
        page.addView(text("连接、备份与数据管理", 14, color(R.color.text_secondary), false), matchWrapParams(5));

        LinearLayout lanCard = card();
        lanCard.addView(text("PC 访问", 18, color(R.color.text_primary), true));
        lanStatusView = text("", 14, color(R.color.text_secondary), false);
        lanCard.addView(lanStatusView, matchWrapParams(7));
        lanToggleView = action("开启访问", ACTION_PRIMARY);
        lanToggleView.setOnClickListener(view -> { LanSessionState state = lanSessionManager.getState(); if (state.getStatus() == LanSessionState.Status.AWAITING_CODE || state.getStatus() == LanSessionState.Status.CONNECTED) { ((PasswordVaultApplication) getApplication()).stopLanAccess(); } else requestLanAccess(); updateLanAccessCard(); });
        lanCard.addView(lanToggleView, matchWrapParams(14));
        page.addView(lanCard, matchWrapParams(18));
        LinearLayout backupCard = card();
        backupCard.addView(text("加密备份", 18, color(R.color.text_primary), true));
        backupCard.addView(text(
                "导出全部密码、分类和标签；导入前会先显示数量，确认后覆盖本机全部数据。",
                14,
                color(R.color.text_secondary),
                false
        ), matchWrapParams(7));
        LinearLayout backupActions = horizontalRow();
        TextView export = action(getString(R.string.backup_export), ACTION_PRIMARY);
        export.setId(R.id.export_backup);
        export.setOnClickListener(view -> launchExportPicker());
        backupActions.addView(export, weightedParams());
        TextView importBackup = action(getString(R.string.backup_import), ACTION_SECONDARY);
        importBackup.setId(R.id.import_backup);
        importBackup.setOnClickListener(view -> launchImportPicker());
        backupActions.addView(importBackup, weightedMarginParams(8));
        backupCard.addView(backupActions, matchWrapParams(14));
        page.addView(backupCard, matchWrapParams(12));

        LinearLayout dangerCard = card();
        dangerCard.addView(text("清空全部数据", 18, color(R.color.danger), true));
        dangerCard.addView(text(
                "永久删除所有密码、分类和标签。此操作需要两次确认，且无法撤销。",
                14,
                color(R.color.text_secondary),
                false
        ), matchWrapParams(7));
        TextView clear = action("清空全部数据", ACTION_DANGER);
        clear.setOnClickListener(view -> confirmClearAllFirst());
        dangerCard.addView(clear, matchWrapParams(14));
        page.addView(dangerCard, matchWrapParams(20));

        page.addView(text("本地离线版 · 0.1.0", 13, color(R.color.text_secondary), false), matchWrapParams(18));

        setContent(scroll);
        updateNavigation();
        updateLanAccessCard();
        lanStatusHandler.removeCallbacks(lanStatusRefresh);
        lanStatusHandler.postDelayed(lanStatusRefresh, 750L);
    }

    private void updateLanAccessCard() {
        if (lanStatusView == null || lanToggleView == null) return;
        LanSessionState state = lanSessionManager.getState();
        boolean running = state.getStatus() == LanSessionState.Status.AWAITING_CODE || state.getStatus() == LanSessionState.Status.CONNECTED;
        String url = ((PasswordVaultApplication) getApplication()).getLanAccessUrl();
        String address = url == null ? "正在准备局域网地址" : url;
        if (state.getStatus() == LanSessionState.Status.CONNECTED) {
            lanStatusView.setText("访问地址：" + address + "\n状态：PC 已连接");
        } else if (state.getStatus() == LanSessionState.Status.AWAITING_CODE) {
            lanStatusView.setText("访问地址：" + address + "\n访问码：" + state.getAccessCode());
        } else {
            lanStatusView.setText("开启后显示局域网地址和 6 位访问码；停止后立即断开。");
        }
        lanToggleView.setText(running ? "停止访问" : "开启访问");
    }

    private void requestLanAccess() {
        List<String> permissions = new ArrayList<String>();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) permissions.add(Manifest.permission.POST_NOTIFICATIONS);
        if (Build.VERSION.SDK_INT >= 37 && checkSelfPermission(Manifest.permission.ACCESS_LOCAL_NETWORK) != PackageManager.PERMISSION_GRANTED) permissions.add(Manifest.permission.ACCESS_LOCAL_NETWORK);
        if (!permissions.isEmpty()) { requestPermissions(permissions.toArray(new String[0]), REQUEST_LAN_PERMISSIONS); return; }
        startLanService();
    }

    @Override public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] results) {
        super.onRequestPermissionsResult(requestCode, permissions, results);
        if (requestCode != REQUEST_LAN_PERMISSIONS) return;
        if (results.length == 0) { Toast.makeText(this, "未授予局域网访问所需权限，无法开启 PC 访问。", Toast.LENGTH_LONG).show(); return; }
        for (int result : results) if (result != PackageManager.PERMISSION_GRANTED) { Toast.makeText(this, "未授予局域网访问所需权限，无法开启 PC 访问。", Toast.LENGTH_LONG).show(); return; }
        startLanService();
    }

    private void startLanService() {
        try {
            startForegroundService(LanAccessService.startIntent(this));
            Toast.makeText(this, "正在开启 PC 访问", Toast.LENGTH_SHORT).show();
        } catch (RuntimeException exception) {
            Toast.makeText(this, "无法开启 PC 访问，请检查系统权限后重试。", Toast.LENGTH_LONG).show();
        }
    }

    private void launchExportPicker() {
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT)
                .addCategory(Intent.CATEGORY_OPENABLE)
                .setType("application/octet-stream")
                .putExtra(Intent.EXTRA_TITLE, "password-vault-backup.pvlb");
        launchBackupPicker(intent, REQUEST_EXPORT_BACKUP);
    }

    private void launchImportPicker() {
        cancelActiveImportPreview();
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT)
                .addCategory(Intent.CATEGORY_OPENABLE)
                .setType("application/octet-stream");
        launchBackupPicker(intent, REQUEST_IMPORT_BACKUP);
    }

    private void launchBackupPicker(Intent intent, int requestCode) {
        try {
            startActivityForResult(intent, requestCode);
        } catch (ActivityNotFoundException exception) {
            showBackupError("无法打开文件选择器，请检查系统文件管理器后重试。");
        }
    }

    private void showBackupPasswordDialog(final Uri uri, final boolean exporting) {
        View content = getLayoutInflater().inflate(R.layout.dialog_backup_password, null);
        final EditText password = content.findViewById(R.id.backup_password);
        final EditText confirmation = content.findViewById(R.id.backup_password_confirmation);
        View confirmationLabel = content.findViewById(R.id.backup_password_confirmation_label);
        confirmation.setVisibility(exporting ? View.VISIBLE : View.GONE);
        confirmationLabel.setVisibility(exporting ? View.VISIBLE : View.GONE);

        final AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(getString(exporting ? R.string.backup_export_title : R.string.backup_import_title))
                .setView(content)
                .setNegativeButton("取消", null)
                .setPositiveButton(exporting ? "导出" : "读取备份", null)
                .create();
        activeBackupDialog = dialog;
        dialog.setOnDismissListener(ignored -> {
            password.setText("");
            confirmation.setText("");
            if (activeBackupDialog == dialog) activeBackupDialog = null;
        });
        dialog.setOnShowListener(ignored -> dialog.getButton(AlertDialog.BUTTON_POSITIVE)
                .setOnClickListener(view -> {
                    char[] passwordChars = password.getText().toString().toCharArray();
                    if (passwordChars.length == 0) {
                        Arrays.fill(passwordChars, '\0');
                        password.setError("备份密码不能为空");
                        password.requestFocus();
                        return;
                    }
                    if (exporting) {
                        char[] confirmationChars = confirmation.getText().toString().toCharArray();
                        boolean matches = Arrays.equals(passwordChars, confirmationChars);
                        Arrays.fill(confirmationChars, '\0');
                        if (!matches) {
                            Arrays.fill(passwordChars, '\0');
                            confirmation.setError("两次输入的备份密码不一致");
                            confirmation.requestFocus();
                            return;
                        }
                        dialog.dismiss();
                        exportBackup(uri, passwordChars);
                    } else {
                        dialog.dismiss();
                        previewImport(uri, passwordChars);
                    }
                }));
        dialog.show();
    }

    private void exportBackup(final Uri uri, final char[] password) {
        submitBackupTask(new Runnable() {
            @Override
            public void run() {
                byte[] backup = null;
                try {
                    backup = backupController.exportBackup(password, password);
                    backupFiles.write(uri, backup);
                    postBackupSuccess("已导出加密备份");
                } catch (Exception exception) {
                    postBackupFailure(exception, false);
                } finally {
                    Arrays.fill(password, '\0');
                    if (backup != null) Arrays.fill(backup, (byte) 0);
                }
            }
        });
    }

    private void previewImport(final Uri uri, final char[] password) {
        submitBackupTask(new Runnable() {
            @Override
            public void run() {
                byte[] backup = null;
                ImportPreview preview = null;
                try {
                    backup = backupFiles.read(uri);
                    preview = backupController.previewImport(backup, password);
                    final ImportPreview completedPreview = preview;
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            if (destroyed || isFinishing()) {
                                safelyCancelPreview(completedPreview);
                                return;
                            }
                            cancelActiveImportPreview();
                            activeImportPreview = completedPreview;
                            showImportPreviewDialog(completedPreview);
                        }
                    });
                } catch (Exception exception) {
                    postBackupFailure(exception, true);
                } finally {
                    Arrays.fill(password, '\0');
                    if (backup != null) Arrays.fill(backup, (byte) 0);
                }
            }
        });
    }

    private void showImportPreviewDialog(final ImportPreview preview) {
        final boolean[] confirmed = new boolean[] {false};
        final AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("确认覆盖本机数据？")
                .setMessage("备份包含 " + preview.getCredentialCount() + " 条密码记录、"
                        + preview.getCategoryCount() + " 个分类和 " + preview.getTagCount()
                        + " 个标签。导入将覆盖本机全部数据，且无法撤销。")
                .setNegativeButton("取消", null)
                .setPositiveButton("导入并覆盖", null)
                .create();
        activeBackupDialog = dialog;
        dialog.setOnDismissListener(ignored -> {
            if (activeBackupDialog == dialog) activeBackupDialog = null;
            if (!confirmed[0] && activeImportPreview == preview) cancelActiveImportPreview();
        });
        dialog.setOnShowListener(ignored -> dialog.getButton(AlertDialog.BUTTON_POSITIVE)
                .setOnClickListener(view -> {
                    confirmed[0] = true;
                    dialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(false);
                    activeImportPreview = null;
                    dialog.dismiss();
                    confirmImport(preview);
                }));
        dialog.show();
    }

    private void confirmImport(final ImportPreview preview) {
        submitBackupTask(new Runnable() {
            @Override
            public void run() {
                try {
                    ((PasswordVaultApplication) getApplication()).runExclusiveVaultMutation(
                            new Runnable() {
                                @Override public void run() {
                                    backupController.confirmImport(preview);
                                }
                            }
                    );
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            if (destroyed || isFinishing()) return;
                            Toast.makeText(MainActivity.this, "已导入并覆盖本机数据", Toast.LENGTH_SHORT).show();
                            showPasswords();
                        }
                    });
                } catch (Exception exception) {
                    postBackupFailure(exception, true);
                }
            }
        });
    }

    private void submitBackupTask(Runnable task) {
        try {
            backupExecutor.execute(task);
        } catch (RejectedExecutionException exception) {
            showBackupError("操作未完成，请重新打开应用后重试。");
        }
    }

    private void postBackupSuccess(final String message) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                if (!destroyed && !isFinishing()) {
                    Toast.makeText(MainActivity.this, message, Toast.LENGTH_SHORT).show();
                }
            }
        });
    }

    private void postBackupFailure(final Exception exception, final boolean importing) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                if (!destroyed && !isFinishing()) {
                    showBackupError(backupErrorMessage(exception, importing));
                }
            }
        });
    }

    private static String backupErrorMessage(Exception exception, boolean importing) {
        if (exception instanceof WrongBackupPasswordException) {
            return "备份密码不正确，现有数据未被修改。";
        }
        if (exception instanceof UnsupportedBackupVersionException) {
            return "此备份版本不受支持，现有数据未被修改。";
        }
        if (exception instanceof CorruptBackupException) {
            return "备份文件已损坏或无效，现有数据未被修改。";
        }
        if (exception instanceof BackupException) {
            return importing ? "导入未完成，现有数据未被修改。" : "导出未完成，请重试。";
        }
        if (exception instanceof IOException) {
            return importing ? "无法读取备份文件，现有数据未被修改。" : "无法写入备份文件，请重试。";
        }
        return importing ? "导入未完成，现有数据未被修改。" : "导出未完成，请重试。";
    }

    private void showBackupError(String message) {
        final AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("操作未完成")
                .setMessage(message)
                .setPositiveButton("知道了", null)
                .create();
        activeBackupDialog = dialog;
        dialog.setOnDismissListener(ignored -> {
            if (activeBackupDialog == dialog) activeBackupDialog = null;
        });
        dialog.show();
    }

    private void cancelActiveImportPreview() {
        ImportPreview preview = activeImportPreview;
        activeImportPreview = null;
        if (preview != null) safelyCancelPreview(preview);
    }

    private void safelyCancelPreview(ImportPreview preview) {
        try {
            backupController.cancelImport(preview);
        } catch (IllegalStateException ignored) {
            // A newer preview has already invalidated this one.
        }
    }

    private void closeVaultAfterBackupWork() {
        // The application owns the encrypted store because the foreground LAN service shares it.
        if (backupExecutor != null) backupExecutor.shutdown();
    }

    boolean isBackupWorkStopped() {
        return backupExecutor == null || backupExecutor.isTerminated();
    }

    AlertDialog getActiveBackupDialog() {
        return activeBackupDialog;
    }

    private void confirmClearAllFirst() {
        new AlertDialog.Builder(this)
                .setTitle("清空全部数据？")
                .setMessage("所有密码、分类和标签都将被永久删除。")
                .setNegativeButton("取消", null)
                .setPositiveButton("继续", (dialog, which) -> confirmClearAllSecond())
                .show();
    }

    private void confirmClearAllSecond() {
        new AlertDialog.Builder(this)
                .setTitle("再次确认")
                .setMessage("此操作无法撤销。确定立即清空本机全部数据吗？")
                .setNegativeButton("取消", null)
                .setPositiveButton("确认清空", (dialog, which) -> {
                    try {
                        ((PasswordVaultApplication) getApplication()).runExclusiveVaultMutation(
                                new Runnable() {
                                    @Override public void run() {
                                        listController.clearAll();
                                    }
                                }
                        );
                        Toast.makeText(this, "已清空全部数据", Toast.LENGTH_SHORT).show();
                        showPasswords();
                    } catch (RuntimeException exception) {
                        showOperationError(exception);
                    }
                })
                .show();
    }

    private void copyText(String label, String value, boolean sensitive) {
        if (isBlank(value)) {
            Toast.makeText(this, "没有可复制的内容", Toast.LENGTH_SHORT).show();
            return;
        }
        ClipboardManager clipboard = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        if (clipboard == null) {
            Toast.makeText(this, "无法访问剪贴板", Toast.LENGTH_SHORT).show();
            return;
        }
        ClipData clip = ClipData.newPlainText(label, value);
        if (sensitive && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            PersistableBundle extras = new PersistableBundle();
            extras.putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true);
            clip.getDescription().setExtras(extras);
        }
        clipboard.setPrimaryClip(clip);
        Toast.makeText(this, "已复制" + label, Toast.LENGTH_SHORT).show();
    }

    private void setContent(View content) {
        if (screen != Screen.MORE) lanStatusHandler.removeCallbacks(lanStatusRefresh);
        if (screen != Screen.PASSWORDS) {
            credentialListContainer = null;
            credentialCountView = null;
        }
        if (screen != Screen.EDITOR) {
            editorPasswordInput = null;
            editorPasswordVisible = false;
        }
        contentContainer.removeAllViews();
        contentContainer.addView(content, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
        ));
    }

    private void updateNavigation() {
        boolean passwordsActive = screen == Screen.PASSWORDS
                || screen == Screen.DETAIL
                || screen == Screen.EDITOR;
        styleNavigationItem(navPasswords, passwordsActive);
        styleNavigationItem(navTaxonomy, screen == Screen.TAXONOMY);
        styleNavigationItem(navMore, screen == Screen.MORE);
    }

    private void styleNavigationItem(TextView view, boolean active) {
        view.setTextColor(color(active ? R.color.primary : R.color.text_secondary));
        view.setTypeface(Typeface.DEFAULT, active ? Typeface.BOLD : Typeface.NORMAL);
        view.setBackgroundColor(color(active ? R.color.primary_soft : R.color.surface));
        view.setClickable(true);
        view.setFocusable(true);
    }

    private LinearLayout verticalPage() {
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(dp(16), dp(18), dp(16), dp(22));
        page.setBackgroundColor(color(R.color.page_background));
        return page;
    }

    private LinearLayout horizontalRow() {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        return row;
    }

    private LinearLayout card() {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(16), dp(15), dp(16), dp(15));
        card.setBackgroundResource(R.drawable.bg_card);
        card.setElevation(dp(1));
        return card;
    }

    private View emptyTaxonomyCard(String label) {
        LinearLayout card = card();
        card.addView(text(label, 14, color(R.color.text_secondary), false));
        return card;
    }

    private LinearLayout errorCard(String message) {
        LinearLayout card = card();
        card.addView(text("无法读取密码库", 17, color(R.color.danger), true));
        card.addView(text(message, 14, color(R.color.text_secondary), false), matchWrapParams(7));
        return card;
    }

    private TextView text(String value, int sizeSp, int textColor, boolean bold) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(sizeSp);
        view.setTextColor(textColor);
        view.setTypeface(Typeface.DEFAULT, bold ? Typeface.BOLD : Typeface.NORMAL);
        view.setLineSpacing(0, 1.08f);
        return view;
    }

    private TextView action(String label, int type) {
        TextView view = text(label, 14, color(R.color.text_primary), true);
        view.setGravity(Gravity.CENTER);
        view.setMinHeight(dp(40));
        view.setPadding(dp(13), dp(8), dp(13), dp(8));
        view.setClickable(true);
        view.setFocusable(true);
        if (type == ACTION_PRIMARY) {
            view.setTextColor(color(R.color.surface));
            view.setBackgroundResource(R.drawable.bg_primary_button);
        } else if (type == ACTION_DANGER) {
            view.setTextColor(color(R.color.danger));
            view.setBackgroundResource(R.drawable.bg_danger_button);
        } else {
            view.setTextColor(color(R.color.text_primary));
            view.setBackgroundResource(R.drawable.bg_secondary_button);
        }
        return view;
    }

    private EditText input(String hint, String value) {
        EditText input = new EditText(this);
        input.setHint(hint);
        input.setText(value == null ? "" : value);
        input.setTextColor(color(R.color.text_primary));
        input.setHintTextColor(color(R.color.text_secondary));
        input.setTextSize(15);
        input.setBackgroundResource(R.drawable.bg_input);
        input.setPadding(dp(12), dp(10), dp(12), dp(10));
        return input;
    }

    private EditText labeledInput(
            LinearLayout form,
            String label,
            String hint,
            String value,
            int inputType,
            boolean multiline
    ) {
        form.addView(text(label, 13, color(R.color.text_secondary), false), matchWrapParams(14));
        EditText input = input(hint, value);
        input.setInputType(inputType);
        input.setSingleLine(!multiline);
        if (multiline) {
            input.setGravity(Gravity.TOP | Gravity.START);
            input.setMinLines(3);
        }
        form.addView(input, matchWrapParams(4));
        return input;
    }

    private void addDetailField(LinearLayout parent, String label, String value) {
        parent.addView(text(label, 12, color(R.color.text_secondary), false), matchWrapParams(14));
        TextView field = text(value, 15, color(R.color.text_primary), false);
        field.setTextIsSelectable(false);
        parent.addView(field, matchWrapParams(4));
    }

    private String taxonomySummary(Credential credential, VaultSnapshot snapshot) {
        List<String> values = new ArrayList<String>();
        Category category = credential.getCategoryId() == null
                ? null
                : snapshot.findCategory(credential.getCategoryId());
        if (category != null) {
            values.add(category.getName());
        } else {
            values.add("未分类");
        }
        for (String tagId : credential.getTagIds()) {
            Tag tag = snapshot.findTag(tagId);
            if (tag != null) {
                values.add("#" + tag.getName());
            }
        }
        StringBuilder result = new StringBuilder();
        for (String value : values) {
            if (result.length() > 0) {
                result.append("  ");
            }
            result.append(value);
        }
        return result.toString();
    }

    private static int usageCountByCategory(VaultSnapshot snapshot, String categoryId) {
        int count = 0;
        for (Credential credential : snapshot.getCredentials()) {
            if (categoryId.equals(credential.getCategoryId())) {
                count++;
            }
        }
        return count;
    }

    private static int usageCountByTag(VaultSnapshot snapshot, String tagId) {
        int count = 0;
        for (Credential credential : snapshot.getCredentials()) {
            if (credential.getTagIds().contains(tagId)) {
                count++;
            }
        }
        return count;
    }

    private void showLoadFailure(RuntimeException exception) {
        screen = Screen.PASSWORDS;
        credentialListContainer = null;
        credentialCountView = null;
        setContent(errorCard(userMessage(exception)));
        updateNavigation();
    }

    private void showOperationError(RuntimeException exception) {
        new AlertDialog.Builder(this)
                .setTitle("操作未完成")
                .setMessage(userMessage(exception))
                .setPositiveButton("知道了", null)
                .show();
    }

    private static String userMessage(RuntimeException exception) {
        if (exception instanceof ValidationException) {
            return exception.getMessage();
        }
        if (exception instanceof ConflictException) {
            return "数据已在其他页面发生变化，请返回刷新后重试。";
        }
        if (exception instanceof NotFoundException) {
            return "记录已不存在，请返回刷新。";
        }
        if (exception instanceof CryptoException) {
            return "密码库校验失败，数据未被修改。";
        }
        return "请重试；如果问题持续，请先不要清空或卸载应用。";
    }

    private int color(int resourceId) {
        return getColor(resourceId);
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private LinearLayout.LayoutParams matchWrapParams(int topMarginDp) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        params.topMargin = dp(topMarginDp);
        return params;
    }

    private LinearLayout.LayoutParams weightedHeightParams(int topMarginDp) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0,
                1f
        );
        params.topMargin = dp(topMarginDp);
        return params;
    }

    private LinearLayout.LayoutParams weightedParams() {
        return new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
    }

    private LinearLayout.LayoutParams weightedMarginParams(int startMarginDp) {
        LinearLayout.LayoutParams params = weightedParams();
        params.leftMargin = dp(startMarginDp);
        return params;
    }

    private LinearLayout.LayoutParams weightedActionParams(int startMarginDp) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f
        );
        params.leftMargin = dp(startMarginDp);
        return params;
    }

    private LinearLayout.LayoutParams marginStartParams(int startMarginDp) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        params.leftMargin = dp(startMarginDp);
        return params;
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    private static String fallback(String value) {
        return isBlank(value) ? "—" : value;
    }

    private interface NameMutation {
        void run(String value);
    }
}
