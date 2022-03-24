package org.openhab.core.internal.auth;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.openhab.core.auth.*;
import org.openhab.core.common.registry.AbstractRegistry;
import org.openhab.core.items.ItemRegistry;
import org.osgi.service.component.annotations.*;

@NonNullByDefault
@Component(service = RoleRegistry.class, immediate = true)
public class RoleRegistryImpl extends AbstractRegistry<Role, String, RoleProvider> implements RoleRegistry {

    private final ItemRegistry itemRegistry;

    /**
     * Constructor.
     *
     */
    @Activate
    public RoleRegistryImpl(@Reference ItemRegistry itemRegistry) {
        super(RoleProvider.class);
        this.itemRegistry = itemRegistry;
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
    public void addRole(String role) {
        ManagedRole managedrole = new ManagedRole(role);
        managedrole.setItemNames(itemRegistry.getAllItemNames());
        add(managedrole);
    }
}
