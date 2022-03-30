package org.openhab.core.io.console.internal.extension;

import java.util.List;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.openhab.core.auth.RoleRegistry;
import org.openhab.core.auth.UserRegistry;
import org.openhab.core.io.console.Console;
import org.openhab.core.io.console.extensions.AbstractConsoleCommandExtension;
import org.openhab.core.io.console.extensions.ConsoleCommandExtension;
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

                default:
                    console.println("Unknown command '" + subCommand + "'");
                    printUsage(console);
                    break;
            }

        } else {
            printUsage(console);
        }
    }

    private String findUsage(String cmd) {
        return getUsages().stream().filter(u -> u.contains(cmd)).findAny().get();
    }
}
