package com.passwordvault.local.core;

public final class CoreTestMain {
    private CoreTestMain() {
    }

    public static void main(String[] args) {
        VaultValidatorTest.run();
        VaultQueryTest.run();
        VaultServiceTest.run();
        VaultBinaryCodecTest.run();
        AesGcmCipherTest.run();
        EncryptedVaultStoreTest.run();
        BackupCryptoTest.run();
        BackupServiceTest.run();
        LanSessionManagerTest.run();
        LanCryptoTest.run();
        LanVaultAccessGateTest.run();
        PhoneUiControllerTest.run();
        PhoneBackupControllerTest.run();
        AndroidDeviceCiContractTest.run();
        System.out.println("PASS CoreTestMain");
    }
}
