package org.openhab.core.io.rest.core.internal.accessControl;

import java.util.Set;

public class UserAccessControl {
    private final String name;

    private Set<String> roles;
    private Set<String> groups;

    public UserAccessControl(String name, Set<String> roles, Set<String> groups) {
        this.name = name;
        this.roles = roles;
        this.groups = groups;
    }

    public String getName() {
        return name;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }

    public Set<String> getGroups() {
        return groups;
    }

    public void setGroups(Set<String> groups) {
        this.groups = groups;
    }
}
