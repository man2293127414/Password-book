package com.passwordvault.local.core.backup;

public final class WrongBackupPasswordException extends BackupException {
    public WrongBackupPasswordException() {
        super("Backup password is incorrect");
    }
}
