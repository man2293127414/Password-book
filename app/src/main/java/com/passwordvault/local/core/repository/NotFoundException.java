package com.passwordvault.local.core.repository;

public final class NotFoundException extends RuntimeException {
    public NotFoundException(String entityType, String id) {
        super(entityType + " not found: id=" + id);
    }
}
