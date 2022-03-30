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

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.openhab.core.auth.Role;
import org.openhab.core.common.registry.DefaultAbstractManagedProvider;
import org.openhab.core.storage.StorageService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

@NonNullByDefault
@Component(service = ManagedRoleProvider.class, immediate = true)
public class ManagedRoleProvider extends DefaultAbstractManagedProvider<Role, String> {

    @Activate
    public ManagedRoleProvider(final @Reference StorageService storageService) {
        super(storageService);
    }

    @Override
    protected String getStorageName() {
        return "roles";
    }

    @Override
    protected String keyToString(String key) {
        return key;
    }
}
