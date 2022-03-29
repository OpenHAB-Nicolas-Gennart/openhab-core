package org.openhab.core.auth;

import java.util.HashSet;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.openhab.core.common.registry.Registry;

@NonNullByDefault
public interface RoleRegistry extends Registry<Role, String> {

    /**
     * Update a role to the registry if it exist. If the role to be modified is administrator, add all the itemNames
     * too.
     *
     * @param oldRole to be replaced
     * @param newRole to put
     */
    public void updateRole(String oldRole, String newRole);

    /**
     * Add a role to the registry if it doesn't exist. If the role is administrator, add all the itemNames too.
     *
     * @param role role to add.
     */
    public void addRole(String role);

    /**
     * Remove the role in the registry if it exist.
     *
     * @param role role to remove
     */
    public void removeRole(String role);

    /**
     * Add all the items to the role in the registry, if the role exist.
     *
     * @param role that will receive new itemNames.
     * @param itemNames to add to the specified role.
     */
    public void addItemsToRole(String role, HashSet<String> itemNames);

    /**
     * Remove all the items to the role in the registry, if the role exist.
     *
     * @param role that will remove itemNames.
     * @param itemNames to remove to the specified role.
     */
    public void removeItemsToRole(String role, HashSet<String> itemNames);
}
