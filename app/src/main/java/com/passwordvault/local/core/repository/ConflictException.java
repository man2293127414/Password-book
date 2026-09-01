package com.passwordvault.local.core.repository;

public final class ConflictException extends RuntimeException {
    public ConflictException(String entityType, String id, int expectedVersion, int actualVersion) {
        super(entityType + " has changed: id=" + id
                + ", expectedVersion=" + expectedVersion
                + ", actualVersion=" + actualVersion);
    }
}
