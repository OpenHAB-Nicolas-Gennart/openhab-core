/**
 * Copyright (c) 2010-2022 Contributors to the openHAB project
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package org.openhab.core.internal.roles;

import java.util.HashSet;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.openhab.core.auth.*;
import org.openhab.core.common.registry.AbstractRegistry;
import org.openhab.core.items.ItemRegistry;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.*;

/**
 * @author Nicolas Gennart
 */
@NonNullByDefault
@Component(service = RoleRegistry.class, immediate = true)
public class RoleRegistryImpl extends AbstractRegistry<Role, String, RoleProvider> implements RoleRegistry {

    private final ItemRegistry itemRegistry;

    public RoleRegistryImpl(@Nullable Class<RoleProvider> providerClazz, ItemRegistry itemRegistry) {
        super(providerClazz);
        this.itemRegistry = itemRegistry;
    }

    /**
     * Constructor.
     *
     */
    @Activate
    public RoleRegistryImpl(BundleContext bundleContext, @Reference ItemRegistry itemRegistry) {
        super(RoleProvider.class);
        super.activate(bundleContext);
        this.itemRegistry = itemRegistry;
    }

    @Override
    @Deactivate
    protected void deactivate() {
        super.deactivate();
    }

    @Reference(cardinality = ReferenceCardinality.OPTIONAL, policy = ReferencePolicy.DYNAMIC)
    protected void setManagedProvider(ManagedRoleProvider managedProvider) {
        super.setManagedProvider(managedProvider);
        super.addProvider(managedProvider);
    }

    protected void unsetManagedProvider(ManagedRoleProvider managedProvider) {
        super.unsetManagedProvider(managedProvider);
        super.removeProvider(managedProvider);
    }

    @Override
    public void changeRole(String oldRole, String newRole) {
        if (get(newRole) != null) {
            throw new IllegalArgumentException("The newRole " + newRole + " already exist in the roleRegistry.");
        }
        ManagedRole managedrole = new ManagedRole(newRole);
        // We check if the oldRole exist.
        if (get(oldRole) != null) {
            if (newRole.equals("administrator")) {
                managedrole.setItemNames(itemRegistry.getAllItemNames());
            }
            remove(oldRole);
            add(managedrole);
        } else {
            throw new IllegalArgumentException(
                    "The role " + oldRole + " does not exist in the roleRegistry so we can't change it.");
        }
    }

    @Override
    public void addRole(String role) {
        ManagedRole managedrole = new ManagedRole(role);
        // We check if the role does not exist.
        if (get(role) == null) {
            if (role.equals("administrator")) {
                managedrole.setItemNames(itemRegistry.getAllItemNames());
            }
            add(managedrole);
        } else {
            throw new IllegalArgumentException(
                    "The role " + role + " already exist in the roleRegistry so we can not add it.");
        }
    }

    @Override
    public void removeRole(String role) {
        // We check if the role exist.
        if (get(role) != null) {
            remove(role);
        } else {
            throw new IllegalArgumentException(
                    "The role " + role + " does not exist in the roleRegistry so we can not remove it.");
        }
    }

    @Override
    public void addItemsToRole(String role, HashSet<String> itemNames) {
        ManagedRole managedRole = (ManagedRole) get(role);
        // We check if the role in the registry exist.
        if (managedRole != null) {
            HashSet<String> roleItemNames = (HashSet<String>) managedRole.getItemNames();
            // We check if the set changed
            if (roleItemNames.addAll(itemNames)) {
                managedRole.setItemNames(roleItemNames);
                update(managedRole);
            }
        } else {
            throw new IllegalArgumentException(
                    "The role " + role + " does not exist in the roleRegistry so we can not add items to it.");
        }
    }

    @Override
    public void removeItemsToRole(String role, HashSet<String> itemNames) {
        ManagedRole managedRole = (ManagedRole) get(role);
        // We check if the role in the registry exist.
        if (managedRole != null) {
            HashSet<String> roleItemNames = (HashSet<String>) managedRole.getItemNames();
            // We check if the set changed
            if (roleItemNames.removeAll(itemNames)) {
                managedRole.setItemNames(roleItemNames);
                update(managedRole);
            }
        } else {
            throw new IllegalArgumentException(
                    "The role " + role + " does not exist in the roleRegistry so we can not remove items to it.");
        }
    }
}
