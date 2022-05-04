package org.openhab.core.io.rest.core.internal.accessControl;

import java.io.IOException;
import java.security.Principal;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Set;

import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.ws.rs.*;
import javax.ws.rs.core.*;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.openhab.core.auth.*;
import org.openhab.core.io.rest.*;
import org.openhab.core.io.rest.auth.VerifyToken;
import org.openhab.core.io.rest.core.internal.item.ItemResource;
import org.openhab.core.io.rest.core.item.EnrichedItemDTO;
import org.openhab.core.items.dto.GroupItemDTO;
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

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
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
        try {
            principal = verifyToken.getPrincipalFromRequestContext(httpHeaders);
        } catch (IOException io) {
            principal = verifyToken.anonymousPrincipal;
        }
        System.out.println(principal.getName());
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
        System.out.println("getAccessControl works");
        System.out.println(resp);
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

    /**
     *
     * @param
     * @return
     */
    @GET
    @PermitAll
    @Path("/role")
    @Produces(MediaType.TEXT_PLAIN)
    @Operation(operationId = "getRoleTest", summary = "Gets the state of an item.", responses = {
            @ApiResponse(responseCode = "200", description = "OK", content = @Content(schema = @Schema(implementation = String.class))),
            @ApiResponse(responseCode = "404", description = "Item not found") })
    public Response getRoleTest() {

        // get item
        System.out.println("It works getRoleTest");
        String gson = new Gson().toJson(getAccessControlObject());
        System.out.println(gson);
        LinkedList<String> linkedList = new LinkedList<>();
        linkedList.add("Gson works");
        System.out.println(new Gson().toJson(linkedList));
        // we cannot use JSONResponse.createResponse() bc. MediaType.TEXT_PLAIN
        // return JSONResponse.createResponse(Status.OK, item.getState().toString(), null);
        return Response.ok(gson).build();
    }

    /**
     * Create or Update an item by supplying an item bean.
     *
     * @return
     */
    @PUT
    @PermitAll
    @Path("/{put: [a-zA-Z_0-9]+}")
    @Consumes(MediaType.APPLICATION_JSON)
    // @Produces(MediaType.TEXT_PLAIN)
    @Operation(operationId = "updateAccessControl", summary = "update access control", responses = {
            @ApiResponse(responseCode = "200", description = "OK", content = @Content(schema = @Schema(implementation = String.class))),
            @ApiResponse(responseCode = "201", description = "Access control updated."),
            @ApiResponse(responseCode = "400", description = "Payload invalid.") })
    public Response updateAccessControl(final @Context UriInfo uriInfo, final @Context HttpHeaders httpHeaders,
            @PathParam("put") @Parameter(description = "put the access control information") String put,
            @Parameter(description = "array of item data", required = true) AccessControl accessControl) {
        /*
         * Principal principal;
         * try {
         * principal = verifyToken.getPrincipalFromRequestContext(httpHeaders);
         * } catch (IOException io) {
         * principal = verifyToken.anonymousPrincipal;
         * }
         * System.out.println(principal.getName());
         * // We check if the user has the administrator access and we verify the token.
         *
         * try {
         * principal = verifyToken.getPrincipalFromRequestContext(httpHeaders);
         * User user = userRegistry.get(principal.getName());
         * if (user != null) {
         * Set<String> roles = user.getRoles();
         * if (!roles.contains("administrator")) {
         * return Response.status(Response.Status.BAD_REQUEST).build();
         * }
         * } else {
         * return Response.status(Response.Status.BAD_REQUEST).build();
         * }
         * } catch (IOException io) {
         * return Response.status(Response.Status.BAD_REQUEST).build();
         * }
         */
        System.out.println("It works PUT!!");
        System.out.println(accessControl);
        System.out.println("roles of accessControl PUT");
        System.out.println(accessControl.getRoles().toString());

        return Response.ok("It works!!!").build();
    }

    /**
     * Create or Update an item by supplying an item bean.
     *
     * @param itemname
     * @param item the item bean.
     * @return
     */
    @PUT
    @RolesAllowed({ Role.ADMIN })
    @Path("/{itemname: [a-zA-Z_0-9]+}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Operation(operationId = "addOrUpdateItemInRegistry", summary = "Adds a new item to the registry or updates the existing item.", security = {
            @SecurityRequirement(name = "oauth2", scopes = { "admin" }) }, responses = {
                    @ApiResponse(responseCode = "200", description = "OK", content = @Content(schema = @Schema(implementation = EnrichedItemDTO.class))),
                    @ApiResponse(responseCode = "201", description = "Item created."),
                    @ApiResponse(responseCode = "400", description = "Payload invalid."),
                    @ApiResponse(responseCode = "404", description = "Item not found or name in path invalid."),
                    @ApiResponse(responseCode = "405", description = "Item not editable.") })
    public Response createOrUpdateItem(final @Context UriInfo uriInfo, final @Context HttpHeaders httpHeaders,
            @HeaderParam(HttpHeaders.ACCEPT_LANGUAGE) @Parameter(description = "language") @Nullable String language,
            @PathParam("itemname") @Parameter(description = "item name") String itemname,
            @Parameter(description = "item data", required = true) @Nullable GroupItemDTO item) {
        System.out.println("success");
        System.out.println(itemname);
        System.out.println(item.toString());

        return Response.ok("creatOrUpdateItemWorks").build();
    }
}
