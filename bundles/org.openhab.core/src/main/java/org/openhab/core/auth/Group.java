package org.openhab.core.auth;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.openhab.core.common.registry.Identifiable;

@NonNullByDefault
public interface Group extends Identifiable<String> {

    public String getGroup();
}
