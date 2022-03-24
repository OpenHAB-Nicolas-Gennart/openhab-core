package org.openhab.core.auth;

import java.util.HashSet;
import java.util.Set;

public class ManagedRole implements Role {

    private final String role;

    private Set<String> itemNames = new HashSet<>();

    public ManagedRole(String role) {
        this.role = role;
    }

    @Override
    public String getRole() {
        return role;
    }

    @Override
    public String getUID() {
        return role;
    }

    public Set<String> getItemNames() {
        return itemNames;
    }

    public void setItemNames(Set<String> itemNames) {
        this.itemNames = itemNames;
    }
}
