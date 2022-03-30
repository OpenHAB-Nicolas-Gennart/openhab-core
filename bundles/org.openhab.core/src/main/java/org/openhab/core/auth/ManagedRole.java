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
package org.openhab.core.auth;

import java.util.HashSet;
import java.util.Set;

/**
 * @author Nicolas Gennart
 */
public class ManagedRole implements Role {

    private final String role;

    private Set<String> itemNames = new HashSet<>();

    public ManagedRole(String role) {
        this.role = role;
    }

    @Override
    public String getRole() {
        return role;
    }

    @Override
    public String getUID() {
        return role;
    }

    public Set<String> getItemNames() {
        return itemNames;
    }

    public void setItemNames(Set<String> itemNames) {
        this.itemNames = itemNames;
    }
}
