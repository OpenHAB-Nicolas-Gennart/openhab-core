package org.openhab.core.auth;

import java.util.HashSet;
import java.util.Set;

public class ManagedGroup implements Group {

    private final String group;

    private Set<String> users = new HashSet<>();

    private Set<String> roles = new HashSet<>();

    public ManagedGroup(String group) {
        this.group = group;
    }

    @Override
    public String getGroup() {
        return group;
    }

    @Override
    public String getUID() {
        return group;
    }

    public Set<String> getUsers() {
        return users;
    }

    public void setUsers(Set<String> users) {
        this.users = users;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }
}
