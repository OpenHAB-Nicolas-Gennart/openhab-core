package org.openhab.core.io.rest.core.internal.accessControl;

import java.io.IOException;
import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

import javax.annotation.security.PermitAll;
import javax.ws.rs.*;
import javax.ws.rs.core.*;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.openhab.core.auth.*;
import org.openhab.core.io.rest.*;
import org.openhab.core.io.rest.auth.VerifyToken;
import org.openhab.core.io.rest.core.internal.item.ItemResource;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.JaxrsWhiteboardConstants;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JSONRequired;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsApplicationSelect;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsName;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;

@Component
@JaxrsResource
@JaxrsName(AccessControlResource.PATH_ACCESS_CONTROL)
@JaxrsApplicationSelect("(" + JaxrsWhiteboardConstants.JAX_RS_NAME + "=" + RESTConstants.JAX_RS_NAME + ")")
@JSONRequired
@Path(AccessControlResource.PATH_ACCESS_CONTROL)
// see https://docs.swagger.io/swagger-core/v2.1.12/apidocs/io/swagger/v3/oas/annotations/tags/Tag.html
@Tag(name = AccessControlResource.PATH_ACCESS_CONTROL)
@NonNullByDefault
public class AccessControlResource implements RESTResource {
    /** The URI path to this resource */
    public static final String PATH_ACCESS_CONTROL = "accessControl";

    private final Logger logger = LoggerFactory.getLogger(ItemResource.class);

    private final UserRegistry userRegistry;
    private final RoleRegistry roleRegistry;
    private final GroupRegistry groupRegistry;
    private final VerifyToken verifyToken;

    @Activate
    public AccessControlResource(final @Reference UserRegistry userRegistry, final @Reference RoleRegistry roleRegistry,
            final @Reference GroupRegistry groupRegistry, final @Reference VerifyToken verifyToken) {

        this.userRegistry = userRegistry;
        this.roleRegistry = roleRegistry;
        this.groupRegistry = groupRegistry;
        this.verifyToken = verifyToken;
    }

    @GET
    @PermitAll
    @Produces(MediaType.TEXT_PLAIN)
    @Operation(operationId = "getAccessControl", summary = "Gets the information from the role-based access control model.", responses = {
            @ApiResponse(responseCode = "200", description = "OK", content = @Content(schema = @Schema(implementation = String.class))),
            @ApiResponse(responseCode = "404", description = "AccessControl not found") })
    public Response getAccessControl(final @Context UriInfo uriInfo, final @Context HttpHeaders httpHeaders) {
        Principal principal;

        // We check if the user has the administrator access and we verify the token.
        try {
            principal = verifyToken.getPrincipalFromRequestContext(httpHeaders);
            User user = userRegistry.get(principal.getName());
            if (user != null) {
                Set<String> roles = user.getRoles();
                if (!roles.contains("administrator")) {
                    return Response.status(Response.Status.BAD_REQUEST).build();
                }
            } else {
                return Response.status(Response.Status.BAD_REQUEST).build();
            }
        } catch (IOException io) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
        Gson gson = new Gson();
        String resp = gson.toJson(getAccessControlObject());
        return Response.ok(resp).build();
    }

    private AccessControl getAccessControlObject() {
        HashSet<UserAccessControl> userAccessControls = new HashSet<>();
        for (User user : userRegistry.getAll()) {
            UserAccessControl userAccessControl = new UserAccessControl(user.getName(), user.getRoles(),
                    user.getGroups());
            userAccessControls.add(userAccessControl);
        }
        return new AccessControl(userAccessControls, (HashSet<Group>) groupRegistry.getAll(),
                (HashSet<Role>) roleRegistry.getAll());
    }

    @PUT
    @PermitAll
    @Path("/put")
    @Consumes(MediaType.TEXT_PLAIN)
    @Operation(operationId = "updateAccessControl", summary = "update access control information.", responses = {
            @ApiResponse(responseCode = "200", description = "OK", content = @Content(schema = @Schema(implementation = String.class))),
            @ApiResponse(responseCode = "404", description = "Access Control not found.") })
    public Response updateAccessControl(final @Context UriInfo uriInfo, final @Context HttpHeaders httpHeaders,
            @Parameter(description = "access control information") String accessControlStr) throws IOException {

        Principal principal;

        // We check if the user has the administrator access and we verify the token.
        try {
            principal = verifyToken.getPrincipalFromRequestContext(httpHeaders);
            User user = userRegistry.get(principal.getName());
            if (user != null) {
                Set<String> roles = user.getRoles();
                if (!roles.contains("administrator")) {
                    return Response.status(Response.Status.BAD_REQUEST).build();
                }
            } else {
                return Response.status(Response.Status.BAD_REQUEST).build();
            }
        } catch (IOException io) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        JsonObject jsonObject = new Gson().fromJson(accessControlStr, JsonObject.class);
        AccessControl accessControl = jsonObjectToAccessControlObject(jsonObject);
        updateAccessControlRegistry(accessControl);

        return Response.ok("success").build();
    }

    /**
     * Transform the receive JsonObject from the client side to an AccessControl object.
     *
     * @param jsonObject receive from the client side
     * @return an AccessControl object
     */
    private AccessControl jsonObjectToAccessControlObject(JsonObject jsonObject) {
        // We get the users access control.
        Set<UserAccessControl> accessControl = new HashSet<>();
        for (JsonElement jsonElementUserAccessControl : jsonObject.get("userAccessControlSet").getAsJsonArray()) {
            try {
                JsonObject jsonObjectUserAccessControl = jsonElementUserAccessControl.getAsJsonObject();

                String userName = jsonObjectUserAccessControl.get("name").getAsString();
                Set<String> userRoles = new HashSet<>();
                for (JsonElement jsonElementUserRole : jsonObjectUserAccessControl.get("roles").getAsJsonArray()) {
                    userRoles.add(jsonElementUserRole.getAsString());
                }
                Set<String> userGroups = new HashSet<>();
                for (JsonElement jsonElementUserGroup : jsonObjectUserAccessControl.get("groups").getAsJsonArray()) {
                    userGroups.add(jsonElementUserGroup.getAsString());
                }
                UserAccessControl userAccessControl = new UserAccessControl(userName, userRoles, userGroups);
                accessControl.add(userAccessControl);
            } catch (IllegalStateException ignored) {

            }
        }

        // We get the groups.
        Set<Group> groups = new HashSet<>();
        for (JsonElement jsonElementGroups : jsonObject.get("groups").getAsJsonArray()) {
            try {
                JsonObject jsonObjectGroup = jsonElementGroups.getAsJsonObject();

                String groupName = jsonObjectGroup.get("group").getAsString();

                Set<String> roles = new HashSet<>();
                for (JsonElement jsonElementRole : jsonObjectGroup.get("roles").getAsJsonArray()) {
                    roles.add(jsonElementRole.getAsString());
                }
                ManagedGroup managedGroup = new ManagedGroup(groupName);
                managedGroup.setRoles(roles);
                groups.add(managedGroup);
            } catch (IllegalStateException ignored) {

            }
        }
        // We get the roles.
        Set<Role> roles = new HashSet<>();
        for (JsonElement jsonElementRoles : jsonObject.get("roles").getAsJsonArray()) {
            try {
                JsonObject jsonObjectRole = jsonElementRoles.getAsJsonObject();

                String roleName = jsonObjectRole.get("role").getAsString();

                Set<String> itemNames = new HashSet<>();
                for (JsonElement jsonElementItem : jsonObjectRole.get("items").getAsJsonArray()) {
                    itemNames.add(jsonElementItem.getAsString());
                }
                ManagedRole managedRole = new ManagedRole(roleName);
                managedRole.setItemNames(itemNames);
                roles.add(managedRole);
            } catch (IllegalStateException ignored) {

            }
        }
        return new AccessControl(accessControl, groups, roles);
    }

    /**
     * Update the AccessControl object in the UserRegistry, GroupRegistry and RoleRegistry.
     *
     * @param accessControl object that has to be put to the registries.
     */
    private void updateAccessControlRegistry(AccessControl accessControl) {

        // Update the users
        for (UserAccessControl userAccessControl : accessControl.getUserAccessControlSet()) {
            ManagedUser managedUser = (ManagedUser) userRegistry.get(userAccessControl.getName());
            if (managedUser != null) {
                Set<String> groups = managedUser.getGroups();
                groups.addAll(userAccessControl.getGroups());
                managedUser.setGroups(groups);

                Set<String> roles = managedUser.getRoles();
                roles.addAll(userAccessControl.getRoles());
                managedUser.setRoles(roles);

                userRegistry.update(managedUser);
            }
        }
        // Update the groups
        for (Group newGroup : accessControl.getGroups()) {
            ManagedGroup managedGroup = (ManagedGroup) groupRegistry.get(newGroup.getGroup());
            if (managedGroup != null) {
                Set<String> roles = managedGroup.getRoles();
                ManagedGroup managedNewGroup = (ManagedGroup) newGroup;
                roles.addAll(managedNewGroup.getRoles());
                managedGroup.setRoles(roles);
                groupRegistry.update(managedGroup);
            } else {
                groupRegistry.add(newGroup);
            }
        }

        // Update the roles
        for (Role newRole : accessControl.getRoles()) {
            ManagedRole managedRole = (ManagedRole) roleRegistry.get(newRole.getRole());
            if (managedRole != null) {
                Set<String> itemNames = managedRole.getItemNames();
                ManagedRole managedNewRole = (ManagedRole) newRole;
                itemNames.addAll(managedNewRole.getItemNames());
                managedRole.setItemNames(itemNames);
                roleRegistry.update(managedRole);
            } else {
                roleRegistry.add(newRole);
            }
        }
    }
}
