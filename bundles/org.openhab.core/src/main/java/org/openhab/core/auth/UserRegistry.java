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

import java.util.Set;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.openhab.core.common.registry.Registry;

/**
 * An interface for a generic {@link Registry} of {@link User} entities. User registries can also be used as
 * {@link AuthenticationProvider}.
 *
 * @author Yannick Schaus - initial contribution
 *
 */
@NonNullByDefault
public interface UserRegistry extends Registry<User, String>, AuthenticationProvider {

    /**
     * Adds a new {@link User} in this registry. The implementation receives the clear text credentials and is
     * responsible for their secure storage (for instance by hashing the password), then return the newly created
     * {@link User} instance.
     *
     * @param username the username of the new user
     * @param password the user password
     * @param roles the roles attributed to the new user
     * @return the new registered {@link User} instance
     */
    public User register(String username, String password, Set<String> roles);

    /**
     *
     * Change the role for an {@link User} in this registry.
     *
     * @param user informations of the user
     * @param oldRole old role to be replace
     * @param newRole new role that will be replace
     *            Change the role of a user. If the user has more than one role, replace only the role to be replaced.
     */
    public void changeRole(String user, String oldRole, String newRole);

    /**
     * Add a role for an {@link User} in this registry.
     *
     * @param user informations of the user
     * @param role role to be added
     * @return return true if the role is added and false otherwise.
     */
    public boolean addRole(String user, String role);

    /**
     * Remove the specific role of the user
     *
     * @param user informations of the user
     * @param role role to be added
     * @return return true if the role is removed and false otherwise.
     */
    public boolean removeRole(String user, String role);

    /**
     * Checks if in the user registry there is a user with the role specified in the argument.
     *
     * @param role verify if a user has this role in the user registry.
     * @return return true if at least a user in the user registry has the role and false otherwise.
     */
    public boolean containRole(String role);

    /**
     * Count the number of user with the role administrator.
     *
     * @param role role to be count
     * @return the number of time the role is present in the user registry
     */
    public int countRole(String role);

    /**
     *
     * Change the group for an {@link User} in this registry.
     *
     * @param user information of the user
     * @param oldGroup old group to be replaced
     * @param newGroup new group that will be replaced
     */
    public void changeGroup(String user, String oldGroup, String newGroup);

    /**
     * Add the group to the user in the registry, if the group and the user exist.
     *
     * @param user that will receive a new group.
     * @param group to add to the specified user.
     */
    public boolean addGroup(String user, String group);

    /**
     * Remove the group to the user in the registry, if the group and teh user exist.
     *
     * @param user that will remove group.
     * @param group to remove to the specified group.
     */
    public boolean removeGroup(String user, String group);

    /**
     * Change the password for an {@link User} in this registry. The implementation receives the new password and is
     * responsible for their secure storage (for instance by hashing the password).
     *
     * @param user the username of the existing user
     * @param newPassword the new password
     */
    public void changePassword(User user, String newPassword);

    /**
     * Check if the password of the user with administrator role is correct.
     *
     * @param user the user with the role administrator.
     * @param password the password of the user with the role administrator.
     * @return true if the password of the user is correct and if the user has the administrator role, return false
     *         otherwise.
     */
    public boolean checkAdministratorCredential(User user, String password);

    /**
     * Adds a new session to the user profile
     *
     * @param user the user
     * @param session the session to add
     */
    public void addUserSession(User user, UserSession session);

    /**
     * Removes the specified session from the user profile
     *
     * @param user the user
     * @param session the session to remove
     */
    public void removeUserSession(User user, UserSession session);

    /**
     * Clears all sessions from the user profile
     *
     * @param user the user
     */
    public void clearSessions(User user);

    /**
     * Adds a new API token to the user profile. The implementation is responsible for storing the token in a secure way
     * (for instance by hashing it).
     *
     * @param user the user
     * @param name the name of the API token to create
     * @param scope the scope this API token will be valid for
     * @return the string that can be used as a Bearer token to match the new API token
     */
    public String addUserApiToken(User user, String name, String scope);

    /**
     * Removes the specified API token from the user profile
     *
     * @param user the user
     * @param apiToken the API token
     */
    public void removeUserApiToken(User user, UserApiToken apiToken);
}
