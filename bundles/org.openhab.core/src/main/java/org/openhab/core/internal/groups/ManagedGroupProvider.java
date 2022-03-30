package org.openhab.core.internal.groups;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.openhab.core.auth.Group;
import org.openhab.core.common.registry.DefaultAbstractManagedProvider;
import org.openhab.core.storage.StorageService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

@NonNullByDefault
@Component(service = ManagedGroupProvider.class, immediate = true)
public class ManagedGroupProvider extends DefaultAbstractManagedProvider<Group, String> {

    @Activate
    public ManagedGroupProvider(final @Reference StorageService storageService) {
        super(storageService);
    }

    @Override
    protected String getStorageName() {
        return "groups";
    }

    @Override
    protected String keyToString(String key) {
        return key;
    }
}
