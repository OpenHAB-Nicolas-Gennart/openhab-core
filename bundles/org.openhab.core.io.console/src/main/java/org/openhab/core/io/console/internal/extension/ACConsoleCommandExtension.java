package org.openhab.core.io.console.internal.extension;

import java.util.*;
import java.util.stream.Collectors;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.openhab.core.auth.*;
import org.openhab.core.io.console.Console;
import org.openhab.core.io.console.extensions.AbstractConsoleCommandExtension;
import org.openhab.core.io.console.extensions.ConsoleCommandExtension;
import org.openhab.core.items.Item;
import org.openhab.core.items.ItemRegistry;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component(service = ConsoleCommandExtension.class)
@NonNullByDefault
public class ACConsoleCommandExtension extends AbstractConsoleCommandExtension {

    private static final String SUBCMD_LISTAC = "listAC";

    private static final String SUBCMD_LISTGROUPS = "listGroups";
    private static final String SUBCMD_CHANGEGROUP = "changeGroup";
    private static final String SUBCMD_ADDGROUP = "addGroup";
    private static final String SUBCMD_REMOVEGROUP = "rmvGroup";

    private static final String SUBCMD_ADDROLETOGROUP = "addRoleToGroup";
    private static final String SUBCMD_RMVROLETOGROUP = "rmvRoleToGroup";

    private static final String SUBCMD_LISTROLES = "listRoles";
    private static final String SUBCMD_CHANGEROLE = "changeRole";
    private static final String SUBCMD_ADDROLE = "addRole";
    private static final String SUBCMD_REMOVEROLE = "rmvRole";

    private static final String SUBCMD_ADDITEMTOROLE = "addItemToRole";
    private static final String SUBCMD_RMVITEMTOROLE = "rmvItemToRole";

    private final Logger logger = LoggerFactory.getLogger(ACConsoleCommandExtension.class);

    private final UserRegistry userRegistry;
    private final ItemRegistry itemRegistry;
    private final RoleRegistry roleRegistry;
    private final GroupRegistry groupRegistry;

    @Activate
    public ACConsoleCommandExtension(final @Reference UserRegistry userRegistry,
            final @Reference ItemRegistry itemRegistry, final @Reference RoleRegistry roleRegistry,
            final @Reference GroupRegistry groupRegistry) {
        super("ac", "manage the role-based access control.");
        this.userRegistry = userRegistry;
        this.itemRegistry = itemRegistry;
        this.roleRegistry = roleRegistry;
        this.groupRegistry = groupRegistry;
    }

    @Override
    public List<String> getUsages() {
        return List.of(buildCommandUsage(SUBCMD_LISTAC, "The role-based access control model will be display"),

                buildCommandUsage(SUBCMD_LISTGROUPS,
                        "lists the groups and the users that contain them in the registry"),
                buildCommandUsage(SUBCMD_CHANGEGROUP + " <oldGroup> <newGroup>",
                        "changes the group name in the registry"),
                buildCommandUsage(SUBCMD_ADDGROUP + " <group>", "adds the group in the registry"),
                buildCommandUsage(SUBCMD_REMOVEGROUP + " <group>", "removes the group in the registry"),

                buildCommandUsage(SUBCMD_ADDROLETOGROUP + " <group> <role>",
                        "adds the specified role in the specified group"),
                buildCommandUsage(SUBCMD_RMVROLETOGROUP + " <group> <role>",
                        "removes the specified role in the specified group"),

                buildCommandUsage(SUBCMD_LISTROLES, "lists the roles in the registry"),
                buildCommandUsage(SUBCMD_CHANGEROLE + " <oldRole> <newRole>", "changes the role name in the registry"),
                buildCommandUsage(SUBCMD_ADDROLE + " <role>", "adds the role in the registry"),
                buildCommandUsage(SUBCMD_REMOVEROLE + " <role>", "removes the role in the registry"),

                buildCommandUsage(SUBCMD_ADDITEMTOROLE + " <role> <itemName>", "adds the specified item to the role"),
                buildCommandUsage(SUBCMD_RMVITEMTOROLE + " <role> <itemName>",
                        "removes the specified item to the role"));
    }

    @Override
    public void execute(String[] args, Console console) {
        if (args.length > 0) {
            String subCommand = args[0];
            switch (subCommand) {
                case SUBCMD_LISTAC:
                    if (args.length == 1) {
                        Collection<Role> roles = roleRegistry.getAll();
                        HashSet<ManagedRole> managedRoles = (HashSet<ManagedRole>) roles.stream()
                                .map(role -> (ManagedRole) role).collect(Collectors.toSet());

                        Collection<Group> groups = groupRegistry.getAll();
                        HashSet<ManagedGroup> managedGroups = (HashSet<ManagedGroup>) groups.stream()
                                .map(group -> (ManagedGroup) group).collect(Collectors.toSet());

                        System.out.println("----------------------------------");
                        System.out.println("<ROLE-BASED ACCESS CONTROL MODEL>");
                        System.out.println("----------------------------------");
                        System.out.println("GROUPS");
                        for (ManagedGroup managedGroup : managedGroups) {
                            printGroupWithRoles(managedGroup.getGroup(), managedGroup.getRoles());
                        }
                        System.out.println("ROLES");
                        for (ManagedRole managedRole : managedRoles) {
                            printRoleWithItems(managedRole.getRole(), managedRole.getItemNames());
                        }

                    } else {
                        console.printUsage(findUsage(SUBCMD_LISTAC));
                    }
                    break;
                case SUBCMD_LISTGROUPS:
                    if (args.length == 1) {
                        printAllGroups();
                    } else {
                        console.printUsage(findUsage(SUBCMD_LISTGROUPS));
                    }
                    break;
                case SUBCMD_CHANGEGROUP:
                    if (args.length == 3) {
                        try {
                            // We change the group for the user.
                            for (User user : userRegistry.getAll()) {
                                if (user.getGroups().contains(args[1])) {
                                    userRegistry.changeGroup(user.getUID(), args[1], args[2]);
                                }
                            }

                            groupRegistry.changeGroup(args[1], args[2]);

                            console.println(
                                    "The group (" + args[1] + ") has been changed to the group (" + args[2] + ")");
                        } catch (IllegalArgumentException ie) {
                            logger.warn("IllegalArgumentException: ", ie);
                            console.println("Look at your logs with the command <log:tail>.");
                            printAllRoles();
                        }
                    } else {
                        console.printUsage(findUsage(SUBCMD_CHANGEGROUP));
                    }

                    break;
                case SUBCMD_ADDGROUP:
                    if (args.length == 2) {
                        try {
                            groupRegistry.addGroup(args[1]);
                        } catch (IllegalArgumentException ie) {
                            logger.warn("IllegalArgumentException: ", ie);
                            console.println("Look at your logs with the command <log:tail>.");
                            printAllRoles();
                        }

                    } else {
                        console.printUsage(findUsage(SUBCMD_ADDGROUP));
                    }
                    break;
                case SUBCMD_REMOVEGROUP:
                    if (args.length == 2) {
                        try {
                            // We remove the group for the users.
                            for (User user : userRegistry.getAll()) {
                                if (user.getGroups().contains(args[1])) {
                                    userRegistry.removeGroup(user.getUID(), args[1]);
                                }
                            }

                            groupRegistry.removeGroup(args[1]);
                        } catch (IllegalArgumentException ie) {
                            logger.warn("IllegalArgumentException: ", ie);
                            console.println("Look at your logs with the command <log:tail>.");
                            printAllRoles();
                        }
                    } else {
                        console.printUsage(findUsage(SUBCMD_REMOVEGROUP));
                    }
                    break;
                case SUBCMD_ADDROLETOGROUP:
                    if (args.length == 3) {
                        try {
                            groupRegistry.addRoleToGroup(args[1], args[2]);
                            System.out.println("The group is added!");
                            System.out.println("Here you can see the group " + args[1] + " and his actual role(s) : ");
                            ManagedGroup managedGroup = (ManagedGroup) groupRegistry.get(args[1]);
                            if (managedGroup != null) {
                                printGroupWithRoles(managedGroup.getGroup(), managedGroup.getRoles());
                            }
                        } catch (IllegalArgumentException ie) {
                            logger.warn("IllegalArgumentException: ", ie);
                            console.println("Look at your logs with the command <log:tail>.");
                        }
                    } else {
                        console.printUsage(findUsage(SUBCMD_ADDROLETOGROUP));
                    }
                    break;
                case SUBCMD_RMVROLETOGROUP:
                    if (args.length == 3) {
                        try {
                            groupRegistry.removeRoleToGroup(args[1], args[2]);
                            System.out.println("The group is rmoved!");
                            System.out.println("Here you can see the group " + args[2] + " and his actual role(s) : ");
                            ManagedGroup managedGroup = (ManagedGroup) groupRegistry.get(args[1]);
                            if (managedGroup != null) {
                                printGroupWithRoles(managedGroup.getGroup(), managedGroup.getRoles());
                            }
                        } catch (IllegalArgumentException ie) {
                            logger.warn("IllegalArgumentException: ", ie);
                            console.println("Look at your logs with the command <log:tail>.");
                        }
                    } else {
                        console.printUsage(findUsage(SUBCMD_RMVROLETOGROUP));
                    }
                    break;
                case SUBCMD_LISTROLES:
                    if (args.length == 1) {
                        printAllRoles();
                    } else {
                        console.printUsage(findUsage(SUBCMD_LISTROLES));
                    }
                    break;
                case SUBCMD_CHANGEROLE:
                    if (args.length == 3) {
                        try {
                            if (args[1].equals("administrator")) {
                                console.println("The administrator role cannot be change");
                                return;
                            }
                            if (args[1].equals("user") || args[2].equals("user")) {
                                console.println(
                                        "The user's role cannot be changed because this role is used by default for users who do not have access to any items.");
                            }
                            // We change the role for the user.
                            for (User user : userRegistry.getAll()) {
                                if (user.getRoles().contains(args[1])) {
                                    userRegistry.changeRole(user.getUID(), args[1], args[2]);
                                }
                            }

                            roleRegistry.changeRole(args[1], args[2]);

                            console.println(
                                    "The role (" + args[1] + ") has been changed to the role (" + args[2] + ")");
                        } catch (IllegalArgumentException ie) {
                            logger.warn("IllegalArgumentException: ", ie);
                            console.println("Look at your logs with the command <log:tail>.");
                            printAllRoles();
                        }
                    } else {
                        console.printUsage(findUsage(SUBCMD_CHANGEROLE));
                    }

                    break;
                case SUBCMD_ADDROLE:
                    if (args.length == 2) {
                        try {
                            if (args[1].equals("user")) {
                                console.println(
                                        "The user's role cannot be added because this role is used by default for users who do not have access to any items.");
                            }
                            roleRegistry.addRole(args[1]);
                        } catch (IllegalArgumentException ie) {
                            logger.warn("IllegalArgumentException: ", ie);
                            console.println("Look at your logs with the command <log:tail>.");
                            printAllRoles();
                        }

                    } else {
                        console.printUsage(findUsage(SUBCMD_ADDROLE));
                    }
                    break;
                case SUBCMD_REMOVEROLE:
                    if (args.length == 2) {
                        try {
                            if (args[1].equals("administrator")) {
                                console.println("The administrator role cannot be remove");
                                return;
                            }
                            // We remove the role for the user too.
                            for (User user : userRegistry.getAll()) {
                                if (user.getRoles().contains(args[1])) {
                                    userRegistry.removeRole(user.getUID(), args[1]);
                                }
                            }

                            roleRegistry.removeRole(args[1]);
                        } catch (IllegalArgumentException ie) {
                            logger.warn("IllegalArgumentException: ", ie);
                            console.println("Look at your logs with the command <log:tail>.");
                            printAllRoles();
                        }
                    } else {
                        console.printUsage(findUsage(SUBCMD_REMOVEROLE));
                    }
                    break;
                case SUBCMD_ADDITEMTOROLE:
                    if (args.length == 3) {
                        try {
                            if (args[1].equals("administrator")) {
                                console.println("The administrator role has already access to all items.");
                                return;
                            }
                            if (args[1].equals("user")) {
                                console.println(
                                        "The user's role cannot be managed because this role is used by default for users who do not have access to any items.");
                            }
                            Set<String> items = getAuthorizedItems(args[2]);
                            if (items.size() == 0) {
                                System.out.println("The itemName " + args[2] + " does not exist");
                                System.out.println("The available items are the following:");
                                System.out.println(itemRegistry.getAllItemNames());
                                return;
                            }
                            System.out.println("The added items are as follows:");
                            printSet(items);
                            roleRegistry.addItemsToRole(args[1], (HashSet<String>) items);
                            System.out.println(
                                    "Here you can see the role " + args[2] + " and his actual authorized item(s) : ");
                            ManagedRole managedRole = (ManagedRole) roleRegistry.get(args[1]);
                            if (managedRole != null) {
                                printRoleWithItems(managedRole.getRole(), managedRole.getItemNames());
                            }

                        } catch (IllegalArgumentException ie) {
                            logger.warn("IllegalArgumentException: ", ie);
                            console.println("Look at your logs with the command <log:tail>.");
                        }
                    } else {
                        console.printUsage(findUsage(SUBCMD_REMOVEROLE));
                    }
                    break;
                case SUBCMD_RMVITEMTOROLE:
                    if (args.length == 3) {
                        try {
                            if (args[1].equals("administrator")) {
                                console.println("We cannot remove access to items for the administrator role.");
                                return;
                            }
                            if (args[1].equals("user")) {
                                console.println(
                                        "The user's role cannot be managed because this role is used by default for users who do not have access to any items.");
                            }
                            Set<String> items = getAuthorizedItems(args[2]);
                            if (items.size() == 0) {
                                System.out.println("The itemName " + args[2] + " does not exist");
                                System.out.println("The available item are the following:");
                                System.out.println(itemRegistry.getAllItemNames());
                            } else {
                                System.out.println("The removed items are as follows:");
                                printSet(items);
                                roleRegistry.removeItemsToRole(args[1], (HashSet<String>) items);
                                System.out.println("Here you can see the role " + args[2]
                                        + " and his actual authorized item(s) : ");
                                ManagedRole managedRole = (ManagedRole) roleRegistry.get(args[1]);
                                if (managedRole != null) {
                                    printRoleWithItems(managedRole.getRole(), managedRole.getItemNames());
                                }
                            }
                        } catch (IllegalArgumentException iae) {
                            logger.warn("IllegalArgumentException: ", iae);
                            console.println("Look at your logs with the command <log:tail>.");
                        }
                    } else {
                        console.printUsage(findUsage(SUBCMD_REMOVEROLE));
                    }

                    break;
                default:
                    console.println("Unknown command '" + subCommand + "'");
                    printUsage(console);
                    break;
            }

        } else {
            printUsage(console);
        }
    }

    /**
     * Print all the roles in the roleRegistry.
     */
    private void printAllRoles() {
        Collection<Role> rolesRegistry = roleRegistry.getAll();
        StringBuilder out = new StringBuilder("the roles in the RoleRegistry are the followings: ");
        int c = 0;
        out.append("(");
        for (Role role : rolesRegistry) {
            if (c == 0) {
                out.append(role.getRole());
                c = 1;
            } else {
                out.append(",").append(role.getRole());
            }

        }
        out.append(")");
        System.out.println(out);
    }

    /**
     * Print all the groups in the GroupRegistry.
     */
    private void printAllGroups() {
        Collection<Group> groupsRegistry = groupRegistry.getAll();
        StringBuilder out = new StringBuilder("the groups in the GroupRegistry are the followings: ");
        int c = 0;
        out.append("(");
        for (Group group : groupsRegistry) {
            if (c == 0) {
                out.append(group.getGroup());
                c = 1;
            } else {
                out.append(",").append(group.getGroup());
            }

        }
        out.append(")");
        System.out.println(out);
    }

    /**
     * Print the set of string to the console.
     * 
     * @param prints Set of string to print.
     */
    private void printSet(Set<String> prints) {
        StringBuilder out = new StringBuilder("");
        int c = 0;
        for (String print : prints) {
            if (c == 0) {
                out.append(print);
                c = 1;
            } else {
                out.append(", ").append(print);
            }
        }
        System.out.println(out);
    }

    /**
     * Print the role and all the items to the console.
     *
     * @param role the specified role
     * @param items the set of items
     */
    private void printRoleWithItems(String role, Set<String> items) {
        if (role.equals("administrator")) {
            System.out.println("administrator : (has access to all items)");
        } else if (role.equals("user")) {
            System.out.println("user : (has no access)");
        } else {
            StringBuilder itemsToString = new StringBuilder("(");
            int i = 0;
            for (String item : items) {
                if (i == 0) {
                    itemsToString.append(item);
                    i = 1;
                } else {
                    itemsToString.append(", ").append(item);
                }
            }
            itemsToString.append(")");

            System.out.println(role + ": " + itemsToString);
        }
    }

    /**
     * Print the group and all the roles to the console.
     *
     * @param group the specified group
     * @param roles the set of roles
     */
    private void printGroupWithRoles(String group, Set<String> roles) {

        StringBuilder rolesToString = new StringBuilder("(");
        int i = 0;
        for (String role : roles) {
            if (i == 0) {
                rolesToString.append(role);
                i = 1;
            } else {
                rolesToString.append(", ").append(role);
            }
        }
        rolesToString.append(")");

        System.out.println(group + ": " + rolesToString);
    }

    /**
     * Add the itemName and all his children itemName from the semantic model of OpenHAB .
     *
     * @param itemName the itemName.
     * @return a set of items name
     */
    private Set<String> getAuthorizedItems(String itemName) {
        if (!itemRegistry.getAllItemNames().contains(itemName)) {
            return new HashSet<>();
        }

        Set<Item> items = (Set<Item>) itemRegistry.getAll();

        LinkedList<String> toAdd = new LinkedList<>();
        toAdd.add(itemName);

        Set<String> returnedItems = new HashSet<>();
        returnedItems.add(itemName);

        while (!toAdd.isEmpty()) {
            String headItemName = toAdd.poll();
            for (Item item : items) {
                if (item.getGroupNames().contains(headItemName)) {
                    returnedItems.add(item.getName());
                    toAdd.add(item.getName());
                }
            }
        }
        return returnedItems;
    }

    private String findUsage(String cmd) {
        return getUsages().stream().filter(u -> u.contains(cmd)).findAny().get();
    }
}
