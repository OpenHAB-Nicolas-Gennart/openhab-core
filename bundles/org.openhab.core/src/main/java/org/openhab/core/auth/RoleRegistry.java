package org.openhab.core.auth;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.openhab.core.common.registry.Registry;

@NonNullByDefault
public interface RoleRegistry extends Registry<Role, String> {
    public void addRole(String role);
}
