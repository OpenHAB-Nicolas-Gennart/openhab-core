package org.openhab.core.internal.groups;

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
    private @Reference UserRegistry userRegistry;

    public GroupRegistryImpl(@Nullable Class<GroupProvider> providerClazz, RoleRegistry roleRegistry,
            UserRegistry userRegistry) {
        super(providerClazz);
        this.roleRegistry = roleRegistry;
        this.userRegistry = userRegistry;
    }

    /**
     * Constructor.
     *
     */
    @Activate
    public GroupRegistryImpl(BundleContext bundleContext, @Reference RoleRegistry roleRegistry,
            @Reference UserRegistry userRegistry) {
        super(GroupProvider.class);
        super.activate(bundleContext);
        this.roleRegistry = roleRegistry;
        this.userRegistry = userRegistry;
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
        add(new ManagedGroup("test"));
    }

    @Override
    public void addGroup(String group) {
    }

    @Override
    public void removeGroup(String group) {
    }

    @Override
    public void addUserToGroup(String group, User user) {
    }

    @Override
    public void removeUserToGroup(String group, User user) {
    }

    @Override
    public void addRoleToGroup(String group, User user) {
    }

    @Override
    public void removeRoleToGroup(String group, User user) {
    }
}
