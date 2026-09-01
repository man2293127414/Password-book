package com.passwordvault.local.core.model;

import java.util.Objects;

public final class Category {
    private final String id;
    private final String name;
    private final int version;

    public Category(String id, String name, int version) {
        this.id = id;
        this.name = name;
        this.version = version;
    }

    public String getId() { return id; }
    public String getName() { return name; }
    public int getVersion() { return version; }

    @Override
    public boolean equals(Object other) {
        if (this == other) return true;
        if (!(other instanceof Category)) return false;
        Category that = (Category) other;
        return version == that.version && Objects.equals(id, that.id) && Objects.equals(name, that.name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, name, version);
    }
}
