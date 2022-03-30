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
public class RoleConsoleCommandExtension extends AbstractConsoleCommandExtension {

    private static final String SUBCMD_LISTAC = "listAC";

    private static final String SUBCMD_LISTGROUPS = "listGroups";
    private static final String SUBCMD_CHANGEGROUP = "changeGroup";
    private static final String SUBCMD_ADDGROUP = "addGroup";
    private static final String SUBCMD_REMOVEGROUP = "rmvGroup";

    private static final String SUBCMD_AC_ADDUSERTOGROUP = "addUserToGroup";
    private static final String SUBCMD_AC_RMVUSERTOGROUP = "rmvUserToGroup";

    private static final String SUBCMD_AC_ADDROLETOGROUP = "addRoleToGroup";
    private static final String SUBCMD_AC_RMVROLETOGROUP = "rmvRoleToGroup";

    private static final String SUBCMD_LISTROLES = "listRoles";
    private static final String SUBCMD_CHANGEROLE = "changeRole";
    private static final String SUBCMD_ADDROLE = "addRole";
    private static final String SUBCMD_REMOVEROLE = "removeRole";

    private static final String SUBCMD_AC_ADDITEMTOROLE = "addItemToRole";
    private static final String SUBCMD_AC_RMVITEMTOROLE = "rmvItemToRole";

    private final Logger logger = LoggerFactory.getLogger(RoleConsoleCommandExtension.class);

    private final UserRegistry userRegistry;
    private final ItemRegistry itemRegistry;
    private final RoleRegistry roleRegistry;

    @Activate
    public RoleConsoleCommandExtension(final @Reference UserRegistry userRegistry,
            final @Reference ItemRegistry itemRegistry, final @Reference RoleRegistry roleRegistry) {
        super("ac", "manage the role-based access control.");
        this.userRegistry = userRegistry;
        this.itemRegistry = itemRegistry;
        this.roleRegistry = roleRegistry;
    }

    @Override
    public List<String> getUsages() {
        return List.of(buildCommandUsage(SUBCMD_LISTAC, "The role-based access control model will be display"),

                buildCommandUsage(SUBCMD_LISTGROUPS,
                        "lists the groups and the users that contain them in the registry"),
                buildCommandUsage(SUBCMD_CHANGEGROUP + " <oldRole> <newRole>",
                        "changes the group name in the registry"),
                buildCommandUsage(SUBCMD_ADDGROUP + " <role>", "adds the group in the registry"),
                buildCommandUsage(SUBCMD_REMOVEGROUP + " <role>", "removes the grpup in the registry"),

                buildCommandUsage(SUBCMD_AC_ADDUSERTOGROUP + " <group> <userId>",
                        "adds the user in the specified group."),
                buildCommandUsage(SUBCMD_AC_RMVUSERTOGROUP + " <group> <userId>",
                        "removes the user in the specified group."),

                buildCommandUsage(SUBCMD_AC_ADDROLETOGROUP + " <group> <role>",
                        "adds the specified role in the specified group"),
                buildCommandUsage(SUBCMD_AC_RMVROLETOGROUP + " <group> <role>",
                        "removes the specified role in the specified group"),

                buildCommandUsage(SUBCMD_AC_ADDITEMTOROLE + " <role> <itemName>",
                        "adds the specified item to the role"),
                buildCommandUsage(SUBCMD_AC_RMVITEMTOROLE + " <role> <itemName>",
                        "removes the specified item to the role"),

                buildCommandUsage(SUBCMD_LISTROLES, "lists the roles in the registry"),
                buildCommandUsage(SUBCMD_CHANGEROLE + " <oldRole> <newRole>", "changes the role name in the registry"),
                buildCommandUsage(SUBCMD_ADDROLE + " <role>", "adds the role in the registry"),
                buildCommandUsage(SUBCMD_REMOVEROLE + " <role>", "removes the role in the registry"));
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

                        System.out.println("<ROLE-BASED ACCESS CONTROL MODEL>");
                        for (ManagedRole managedRole : managedRoles) {
                            printRoleWithItems(managedRole.getRole(), managedRole.getItemNames());
                        }

                    } else {
                        console.printUsage(findUsage(SUBCMD_LISTAC));
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
                case SUBCMD_AC_ADDITEMTOROLE:
                    if (args.length == 3) {
                        try {
                            Set<String> items = getAuthorizedItems(args[2]);
                            if (items.size() == 0) {
                                System.out.println("The itemName " + args[2] + " does not exist");
                                System.out.println("The available items are the following:");
                                System.out.println(itemRegistry.getAllItemNames());
                            }
                            try {
                                System.out.println("The added items are as follows:");
                                printSet(items);
                                roleRegistry.addItemsToRole(args[1], (HashSet<String>) items);
                                System.out.println("Here you can see the role " + args[2]
                                        + " and his actual authorized item(s) : ");
                                ManagedRole managedRole = (ManagedRole) roleRegistry.get(args[1]);
                                if (managedRole != null) {
                                    printRoleWithItems(managedRole.getRole(), managedRole.getItemNames());
                                }
                            } catch (IllegalArgumentException iae) {
                                logger.warn("IllegalArgumentException: ", iae);
                                console.println("Look at your logs with the command <log:tail>.");
                            }

                        } catch (IllegalArgumentException ie) {
                            logger.warn("IllegalArgumentException: ", ie);
                            console.println("Look at your logs with the command <log:tail>.");
                        }
                    } else {
                        console.printUsage(findUsage(SUBCMD_REMOVEROLE));
                    }
                    break;
                case SUBCMD_AC_RMVITEMTOROLE:
                    if (args.length == 3) {
                        try {
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
