package com.passwordvault.local.storage;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;
import android.database.sqlite.SQLiteOpenHelper;

import com.passwordvault.local.core.crypto.EncryptedPayload;
import com.passwordvault.local.core.storage.EncryptedBlobStore;

final class VaultDatabase extends SQLiteOpenHelper implements EncryptedBlobStore {
    static final String DATABASE_NAME = "password_vault.db";

    private static final int DATABASE_VERSION = 1;
    static final String TABLE_NAME = "vault_payload";
    private static final String COLUMN_ID = "singleton_id";
    private static final String COLUMN_NONCE = "nonce";
    private static final String COLUMN_CIPHERTEXT = "ciphertext";
    private static final int SINGLETON_ID = 1;

    VaultDatabase(Context context) {
        super(context.getApplicationContext(), DATABASE_NAME, null, DATABASE_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase database) {
        database.execSQL(
                "CREATE TABLE " + TABLE_NAME + " ("
                        + COLUMN_ID + " INTEGER NOT NULL PRIMARY KEY CHECK ("
                        + COLUMN_ID + " = " + SINGLETON_ID + "), "
                        + COLUMN_NONCE + " BLOB NOT NULL, "
                        + COLUMN_CIPHERTEXT + " BLOB NOT NULL)"
        );
    }

    @Override
    public void onUpgrade(SQLiteDatabase database, int oldVersion, int newVersion) {
        throw new SQLiteException(
                "Unsupported vault database upgrade from " + oldVersion + " to " + newVersion
        );
    }

    @Override
    public EncryptedPayload read() {
        Cursor cursor = getReadableDatabase().query(
                TABLE_NAME,
                new String[] {COLUMN_NONCE, COLUMN_CIPHERTEXT},
                COLUMN_ID + " = ?",
                new String[] {Integer.toString(SINGLETON_ID)},
                null,
                null,
                null,
                "1"
        );
        try {
            if (!cursor.moveToFirst()) {
                return null;
            }
            return new EncryptedPayload(cursor.getBlob(0), cursor.getBlob(1));
        } finally {
            cursor.close();
        }
    }

    @Override
    public void replace(EncryptedPayload replacement) {
        if (replacement == null) {
            throw new IllegalArgumentException("replacement must not be null");
        }

        ContentValues values = new ContentValues();
        values.put(COLUMN_ID, SINGLETON_ID);
        values.put(COLUMN_NONCE, replacement.getNonce());
        values.put(COLUMN_CIPHERTEXT, replacement.getCiphertext());

        SQLiteDatabase database = getWritableDatabase();
        database.beginTransaction();
        try {
            long rowId = database.insertWithOnConflict(
                    TABLE_NAME,
                    null,
                    values,
                    SQLiteDatabase.CONFLICT_REPLACE
            );
            if (rowId == -1L) {
                throw new SQLiteException("Unable to replace encrypted vault payload");
            }
            database.setTransactionSuccessful();
        } finally {
            database.endTransaction();
        }
    }
}
