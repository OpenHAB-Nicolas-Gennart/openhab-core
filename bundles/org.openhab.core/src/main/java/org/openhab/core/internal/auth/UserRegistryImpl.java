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
package org.openhab.core.internal.auth;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.openhab.core.auth.*;
import org.openhab.core.common.registry.AbstractRegistry;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The implementation of a {@link UserRegistry} for {@link ManagedUser} entities.
 *
 * @author Yannick Schaus - initial contribution
 * @author Nicolas Gennart - roles management
 */
@NonNullByDefault
@Component(service = UserRegistry.class, immediate = true)
public class UserRegistryImpl extends AbstractRegistry<User, String, UserProvider> implements UserRegistry {

    private final Logger logger = LoggerFactory.getLogger(UserRegistryImpl.class);

    private static final int PASSWORD_ITERATIONS = 65536;
    private static final int APITOKEN_ITERATIONS = 1024;
    private static final String APITOKEN_PREFIX = "oh";
    private static final int KEY_LENGTH = 512;
    private static final String ALGORITHM = "PBKDF2WithHmacSHA512";
    private static final SecureRandom RAND = new SecureRandom();

    private final RoleRegistry roleRegistry;
    private final GroupRegistry groupRegistry;

    @Activate
    public UserRegistryImpl(BundleContext context, Map<String, Object> properties, @Reference RoleRegistry roleRegistry,
            @Reference GroupRegistry groupRegistry) {
        super(UserProvider.class);
        super.activate(context);
        this.roleRegistry = roleRegistry;
        this.groupRegistry = groupRegistry;
    }

    @Override
    @Deactivate
    protected void deactivate() {
        super.deactivate();
    }

    @Reference(cardinality = ReferenceCardinality.OPTIONAL, policy = ReferencePolicy.DYNAMIC)
    protected void setManagedProvider(ManagedUserProvider managedProvider) {
        super.setManagedProvider(managedProvider);
        super.addProvider(managedProvider);
    }

    protected void unsetManagedProvider(ManagedUserProvider managedProvider) {
        super.unsetManagedProvider(managedProvider);
        super.removeProvider(managedProvider);
    }

    @Override
    public User register(String username, String password, Set<String> roles) {
        String passwordSalt = generateSalt(KEY_LENGTH / 8).get();
        String passwordHash = hash(password, passwordSalt, PASSWORD_ITERATIONS).get();
        ManagedUser user = new ManagedUser(username, passwordSalt, passwordHash);

        user.setRoles(new HashSet<>(roles));
        for (String role : roles) {
            if (!role.equals("administrator") && !role.equals("user")) {
                throw new IllegalArgumentException(
                        "The role argument for the function register has to be the role user or the role administrator.");
            }
            if (roleRegistry.get(role) == null) {
                roleRegistry.addRole(role);
            }
        }
        super.add(user);
        return user;
    }

    private Optional<String> generateSalt(final int length) {
        if (length < 1) {
            logger.error("error in generateSalt: length must be > 0");
            return Optional.empty();
        }

        byte[] salt = new byte[length];
        RAND.nextBytes(salt);

        return Optional.of(Base64.getEncoder().encodeToString(salt));
    }

    private Optional<String> hash(String password, String salt, int iterations) {
        char[] chars = password.toCharArray();
        byte[] bytes = salt.getBytes();

        PBEKeySpec spec = new PBEKeySpec(chars, bytes, iterations, KEY_LENGTH);

        Arrays.fill(chars, Character.MIN_VALUE);

        try {
            SecretKeyFactory fac = SecretKeyFactory.getInstance(ALGORITHM);
            byte[] securePassword = fac.generateSecret(spec).getEncoded();
            return Optional.of(Base64.getEncoder().encodeToString(securePassword));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.error("Exception encountered while hashing", e);
            return Optional.empty();
        } finally {
            spec.clearPassword();
        }
    }

    @Override
    public Authentication authenticate(Credentials credentials) throws AuthenticationException {
        if (credentials instanceof UsernamePasswordCredentials) {
            UsernamePasswordCredentials usernamePasswordCreds = (UsernamePasswordCredentials) credentials;
            User user = get(usernamePasswordCreds.getUsername());
            if (user == null) {
                throw new AuthenticationException("User not found: " + usernamePasswordCreds.getUsername());
            }

            ManagedUser managedUser = (ManagedUser) user;
            String hashedPassword = hash(usernamePasswordCreds.getPassword(), managedUser.getPasswordSalt(),
                    PASSWORD_ITERATIONS).get();
            if (!hashedPassword.equals(managedUser.getPasswordHash())) {
                throw new AuthenticationException("Wrong password for user " + usernamePasswordCreds.getUsername());
            }

            return new Authentication(managedUser.getName(), managedUser.getRoles().stream().toArray(String[]::new));
        } else if (credentials instanceof UserApiTokenCredentials) {
            UserApiTokenCredentials apiTokenCreds = (UserApiTokenCredentials) credentials;
            String[] apiTokenParts = apiTokenCreds.getApiToken().split("\\.");
            if (apiTokenParts.length != 3 || !APITOKEN_PREFIX.equals(apiTokenParts[0])) {
                throw new AuthenticationException("Invalid API token format");
            }
            for (User user : getAll()) {
                ManagedUser managedUser = (ManagedUser) user;
                for (UserApiToken userApiToken : managedUser.getApiTokens()) {
                    // only check if the name in the token matches
                    if (!userApiToken.getName().equals(apiTokenParts[1])) {
                        continue;
                    }
                    String[] existingTokenHashAndSalt = userApiToken.getApiToken().split(":");
                    String incomingTokenHash = hash(apiTokenCreds.getApiToken(), existingTokenHashAndSalt[1],
                            APITOKEN_ITERATIONS).get();

                    if (incomingTokenHash.equals(existingTokenHashAndSalt[0])) {
                        return new Authentication(managedUser.getName(),
                                managedUser.getRoles().stream().toArray(String[]::new), userApiToken.getScope());
                    }
                }
            }

            throw new AuthenticationException("Unknown API token");
        }

        throw new IllegalArgumentException("Invalid credential type");
    }

    @Override
    public void changeRole(String user, String oldRole, String newRole) {
        if (roleRegistry.get(oldRole) == null) {
            throw new IllegalArgumentException("The role" + oldRole + " does not exist in the RoleRegistry.");

        }
        if (roleRegistry.get(newRole) == null) {
            throw new IllegalArgumentException("The role " + newRole + "does not exist in the RoleRegistry.");
        }

        if (oldRole.equals(newRole)) {
            return;
        }

        // We make sure that it remains at least one user with the administrator role.
        if (countRole("administrator") == 1 && oldRole.equals("administrator")) {
            throw new IllegalArgumentException(
                    "There must always be at least one user with the administrator role, so we can't remove it.");
        }

        // We check if the user exist in the UserRegistry.
        ManagedUser managedUser = (ManagedUser) get(user);
        if (managedUser == null) {
            throw new IllegalArgumentException("The user " + user + " does not exist.");
        }

        HashSet<String> roles = (HashSet<String>) managedUser.getRoles();

        // We ensure that the user has the role user or the role administrator.
        if (oldRole.equals("administrator") && !newRole.equals("user")) {
            roles.add("user");
        }
        if (oldRole.equals("user") && !newRole.equals("administrator")) {
            throw new IllegalArgumentException("The user has to have the role user or the role administrator");
        }

        // if the role to be changed does not exist throw a new IllegalArgumentException
        if (!roles.contains(oldRole)) {
            throw new IllegalArgumentException(
                    "The role " + oldRole + " does not exist for the user " + user + ", we can't change it.");
        }
        roles.remove(oldRole);
        roles.add(newRole);

        managedUser.setRoles(roles);
        update(managedUser);
    }

    @Override
    public boolean addRole(String user, String role) {
        if (roleRegistry.get(role) == null) {
            throw new IllegalArgumentException("The role " + role + " does not exist in the RoleRegistry.");
        }

        // We check if the user exist in the UserRegistry.
        ManagedUser managedUser = (ManagedUser) get(user);
        if (managedUser == null) {
            throw new IllegalArgumentException("The user " + user + " does not exist.");
        }

        Set<String> roles = managedUser.getRoles();

        boolean ret = roles.add(role);

        managedUser.setRoles(roles);
        update(managedUser);
        return ret;
    }

    @Override
    public boolean removeRole(String user, String role) {

        if (roleRegistry.get(role) == null) {
            throw new IllegalArgumentException("The role " + role + " does not exist in the RoleRegistry.");
        }

        // We make sure that it remains at least one user with the administrator role.
        if (countRole("administrator") == 1 && role.equals("administrator")) {
            throw new IllegalArgumentException(
                    "There must always be at least one user with the administrator role, so we can't remove it.");
        }

        // We check if the user exist in the UserRegistry.
        ManagedUser managedUser = (ManagedUser) get(user);
        if (managedUser == null) {
            throw new IllegalArgumentException("The user " + user + " does not exist.");
        }

        Set<String> roles = managedUser.getRoles();

        // We ensure that the user has the role user or the role administrator.
        if (role.equals("administrator") && !roles.contains("user")) {
            roles.add("user");
        }
        if (role.equals("user") && !roles.contains("administrator")) {
            throw new IllegalArgumentException("The user has to have the role user or the role administrator");
        }

        boolean ret = roles.remove(role);

        managedUser.setRoles(roles);
        update(managedUser);
        return ret;
    }

    @Override
    public boolean containRole(String role) {
        Collection<User> users = super.getAll();
        for (User user : users) {
            if (user.getRoles().contains(role)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public int countRole(String role) {
        int count = 0;
        Collection<User> users = super.getAll();
        for (User user : users) {
            if (user.getRoles().contains(role)) {
                count++;
            }
        }
        return count;
    }

    @Override
    public void changeGroup(String user, String oldGroup, String newGroup) {
        if (groupRegistry.get(oldGroup) == null) {
            throw new IllegalArgumentException("The group" + oldGroup + " does not exist in the GroupRegistry.");

        }
        if (groupRegistry.get(newGroup) == null) {
            throw new IllegalArgumentException("The group " + newGroup + "does not exist in the GroupRegistry.");
        }

        // We check if the user exist in the UserRegistry.
        ManagedUser managedUser = (ManagedUser) get(user);
        if (managedUser == null) {
            throw new IllegalArgumentException("The user " + user + " does not exist.");
        }

        if (oldGroup.equals(newGroup)) {
            return;
        }

        HashSet<String> groups = (HashSet<String>) managedUser.getGroups();

        // if the role to be changed does not exist throw a new IllegalArgumentException
        if (!groups.contains(oldGroup)) {
            throw new IllegalArgumentException(
                    "The group " + oldGroup + " does not exist for the user " + user + ", we can't change it.");
        }
        groups.remove(oldGroup);
        boolean ret = groups.add(newGroup);

        managedUser.setRoles(groups);
        update(managedUser);
    }

    @Override
    public boolean addGroup(String user, String group) {
        // We check if the group exist in the GroupRegistry.
        if (groupRegistry.get(group) != null) {
            ManagedUser managedUser = (ManagedUser) get(user);

            // We check if the user exist in the Registry.
            if (managedUser != null) {
                HashSet<String> groups = (HashSet<String>) managedUser.getGroups();
                // We check if the set changed
                if (groups.add(group)) {
                    managedUser.setGroups(groups);
                    update(managedUser);
                    return true;
                } else {
                    return false;
                }
            } else {
                throw new IllegalArgumentException("The user " + user + " does not exist in the UserRegistry.");
            }
        } else {
            throw new IllegalArgumentException("The group " + group + " does not exist in the GroupRegistry.");
        }
    }

    @Override
    public boolean removeGroup(String user, String group) {
        // We check if the group exist in the GroupRegistry.
        if (groupRegistry.get(group) != null) {
            ManagedUser managedUser = (ManagedUser) get(user);

            // We check if the user exist in the Registry.
            if (managedUser != null) {
                HashSet<String> groups = (HashSet<String>) managedUser.getGroups();
                // We check if the set changed
                if (groups.remove(group)) {
                    managedUser.setGroups(groups);
                    update(managedUser);
                    return true;
                } else {
                    return false;
                }
            } else {
                throw new IllegalArgumentException("The user " + user + " does not exist in the UserRegistry.");
            }
        } else {
            throw new IllegalArgumentException("The group " + group + " does not exist in the GroupRegistry.");
        }
    }

    @Override
    public void changePassword(User user, String newPassword) {
        if (!(user instanceof ManagedUser)) {
            throw new IllegalArgumentException("User is not managed: " + user.getName());
        }

        ManagedUser managedUser = (ManagedUser) user;
        String passwordSalt = generateSalt(KEY_LENGTH / 8).get();
        String passwordHash = hash(newPassword, passwordSalt, PASSWORD_ITERATIONS).get();
        managedUser.setPasswordSalt(passwordSalt);
        managedUser.setPasswordHash(passwordHash);
        update(user);
    }

    @Override
    public boolean checkAdministratorCredential(User user, String password) {
        if (!(user instanceof ManagedUser)) {
            throw new IllegalArgumentException("User is not managed: " + user.getName());
        }
        ManagedUser managedUser = (ManagedUser) user;
        Set<String> roles = managedUser.getRoles();
        if (roles.contains("administrator")) {
            String passwordSalt = managedUser.getPasswordSalt();
            String passwordHash = managedUser.getPasswordHash();

            String checkPasswordHash = hash(password, passwordSalt, PASSWORD_ITERATIONS).get();
            if (passwordHash.equals(checkPasswordHash)) {
                return true;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

    @Override
    public void addUserSession(User user, UserSession session) {
        if (!(user instanceof ManagedUser)) {
            throw new IllegalArgumentException("User is not managed: " + user.getName());
        }

        ManagedUser managedUser = (ManagedUser) user;
        managedUser.getSessions().add(session);
        update(user);
    }

    @Override
    public void removeUserSession(User user, UserSession session) {
        if (!(user instanceof ManagedUser)) {
            throw new IllegalArgumentException("User is not managed: " + user.getName());
        }

        ManagedUser managedUser = (ManagedUser) user;
        managedUser.getSessions().remove(session);
        update(user);
    }

    @Override
    public void clearSessions(User user) {
        if (!(user instanceof ManagedUser)) {
            throw new IllegalArgumentException("User is not managed: " + user.getName());
        }

        ManagedUser managedUser = (ManagedUser) user;
        managedUser.getSessions().clear();
        update(user);
    }

    @Override
    public String addUserApiToken(User user, String name, String scope) {
        if (!(user instanceof ManagedUser)) {
            throw new IllegalArgumentException("User is not managed: " + user.getName());
        }
        if (!name.matches("[a-zA-Z0-9]*")) {
            throw new IllegalArgumentException("API token name format invalid, alphanumeric characters only");
        }

        ManagedUser managedUser = (ManagedUser) user;
        String tokenSalt = generateSalt(KEY_LENGTH / 8).get();
        byte[] rnd = new byte[64];
        RAND.nextBytes(rnd);
        String token = APITOKEN_PREFIX + "." + name + "."
                + Base64.getEncoder().encodeToString(rnd).replaceAll("(\\+|/|=)", "");
        String tokenHash = hash(token, tokenSalt, APITOKEN_ITERATIONS).get();

        UserApiToken userApiToken = new UserApiToken(name, tokenHash + ":" + tokenSalt, scope);

        managedUser.getApiTokens().add(userApiToken);
        update(user);

        return token;
    }

    @Override
    public void removeUserApiToken(User user, UserApiToken userApiToken) {
        if (!(user instanceof ManagedUser)) {
            throw new IllegalArgumentException("User is not managed: " + user.getName());
        }

        ManagedUser managedUser = (ManagedUser) user;
        managedUser.getApiTokens().remove(userApiToken);
        update(user);
    }

    @Override
    public boolean supports(Class<? extends Credentials> type) {
        return (UsernamePasswordCredentials.class.isAssignableFrom(type));
    }
}
