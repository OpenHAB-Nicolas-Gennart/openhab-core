package org.openhab.core.internal.groups;

import java.util.HashSet;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.openhab.core.auth.*;
import org.openhab.core.common.registry.AbstractRegistry;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.*;

/**
 * @author Nicolas Gennart
 */
@NonNullByDefault
@Component(service = GroupRegistry.class, immediate = true)
public class GroupRegistryImpl extends AbstractRegistry<Group, String, GroupProvider> implements GroupRegistry {

    private @Reference RoleRegistry roleRegistry;

    public GroupRegistryImpl(@Nullable Class<GroupProvider> providerClazz, RoleRegistry roleRegistry) {
        super(providerClazz);
        this.roleRegistry = roleRegistry;
    }

    /**
     * Constructor.
     *
     */
    @Activate
    public GroupRegistryImpl(BundleContext bundleContext, @Reference RoleRegistry roleRegistry) {
        super(GroupProvider.class);
        super.activate(bundleContext);
        this.roleRegistry = roleRegistry;
    }

    @Override
    @Deactivate
    protected void deactivate() {
        super.deactivate();
    }

    @Reference(cardinality = ReferenceCardinality.OPTIONAL, policy = ReferencePolicy.DYNAMIC)
    protected void setManagedProvider(ManagedGroupProvider managedProvider) {
        super.setManagedProvider(managedProvider);
        super.addProvider(managedProvider);
    }

    protected void unsetManagedProvider(ManagedGroupProvider managedProvider) {
        super.unsetManagedProvider(managedProvider);
        super.removeProvider(managedProvider);
    }

    @Override
    public void changeGroup(String oldGroup, String newGroup) {
        if (get(newGroup) != null) {
            throw new IllegalArgumentException("The newGroup " + newGroup + " already exist in the GroupRegistry.");
        }

        if (newGroup.equals("administrator") || newGroup.equals("user")) {
            throw new IllegalArgumentException("The group name user or administrator can not be used");
        }
        if (roleRegistry.getAll().contains(newGroup)) {
            throw new IllegalArgumentException("This group name " + newGroup + " is already uses for a role");
        }

        ManagedGroup managedGroup = new ManagedGroup(newGroup);
        // We check if the oldGroup exist.
        if (get(oldGroup) != null) {
            remove(oldGroup);
            add(managedGroup);
        } else {
            throw new IllegalArgumentException(
                    "The group " + oldGroup + " does not exist in the groupRegistry so we can't change it.");
        }
    }

    @Override
    public void addGroup(String group) {
        if (group.equals("administrator") || group.equals("user")) {
            throw new IllegalArgumentException("The group name user or administrator can not be used");
        }
        if (roleRegistry.getAll().contains(group)) {
            throw new IllegalArgumentException("This group name " + group + " is already uses for a role");
        }
        ManagedGroup managedGroup = new ManagedGroup(group);
        // We check if the group does not exist.
        if (get(group) == null) {
            add(managedGroup);
        } else {
            throw new IllegalArgumentException(
                    "The group " + group + " already exist in the GroupRegistry so we can not add it.");
        }
    }

    @Override
    public void removeGroup(String group) {
        // We check if the group exist.
        if (get(group) != null) {
            remove(group);
        } else {
            throw new IllegalArgumentException(
                    "The group " + group + " does not exist in the GroupRegistry so we can not remove it.");
        }
    }

    @Override
    public void addRoleToGroup(String group, String role) {
        // We check if the role exist in the RoleRegistry.
        if (roleRegistry.get(role) != null) {
            ManagedGroup managedGroup = (ManagedGroup) get(group);

            // We check if the role exist in the registry.
            if (managedGroup != null) {
                HashSet<String> roles = (HashSet<String>) managedGroup.getRoles();
                // We check if the set changed
                if (roles.add(role)) {
                    managedGroup.setRoles(roles);
                    update(managedGroup);
                } else {
                    throw new IllegalArgumentException("The role " + role + " is already present in the group.");
                }
            } else {
                throw new IllegalArgumentException(
                        "The group " + group + " does not exist in the GroupRegistry so we can not add items to it.");
            }
        } else {
            throw new IllegalArgumentException(
                    "The role " + role + " does not exist in the RoleRegistry so we can not add it to a group.");
        }
    }

    @Override
    public void removeRoleToGroup(String group, String role) {
        // We check if the role exist in the RoleRegistry.
        if (roleRegistry.get(role) != null) {
            ManagedGroup managedGroup = (ManagedGroup) get(group);

            // We check if the role exist in the registry.
            if (managedGroup != null) {
                HashSet<String> roles = (HashSet<String>) managedGroup.getRoles();
                // We check if the set changed
                if (roles.remove(role)) {
                    managedGroup.setRoles(roles);
                    update(managedGroup);
                } else {
                    throw new IllegalArgumentException("The role " + role + " is not present in the group.");
                }
            } else {
                throw new IllegalArgumentException(
                        "The group " + group + " does not exist in the GroupRegistry so we can not add items to it.");
            }
        } else {
            throw new IllegalArgumentException(
                    "The role " + role + " does not exist in the RoleRegistry so we can not add it to a group.");
        }
    }
}
