package com.passwordvault.local.core.backup;

public final class CorruptBackupException extends BackupException {
    public CorruptBackupException(String message) {
        super(message);
    }

    public CorruptBackupException(String message, Throwable cause) {
        super(message, cause);
    }
}
