package org.openhab.core.io.rest.core.internal.accessControl;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.openhab.core.auth.GroupRegistry;
import org.openhab.core.auth.RoleRegistry;
import org.openhab.core.auth.UserRegistry;
import org.openhab.core.events.EventPublisher;
import org.openhab.core.io.rest.*;
import org.openhab.core.io.rest.auth.VerifyToken;
import org.openhab.core.io.rest.core.internal.item.ItemResource;
import org.openhab.core.io.rest.core.internal.item.MetadataSelectorMatcher;
import org.openhab.core.io.rest.core.item.EnrichedItemDTO;
import org.openhab.core.io.rest.core.item.EnrichedItemDTOMapper;
import org.openhab.core.items.ItemBuilderFactory;
import org.openhab.core.items.ItemRegistry;
import org.openhab.core.items.ManagedItemProvider;
import org.openhab.core.items.MetadataRegistry;
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

import javax.annotation.security.PermitAll;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import java.io.IOException;
import java.security.Principal;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

@Component
@JaxrsResource
@JaxrsName(AccessControlRessource.PATH_ACCESS_CONTROL)
@JaxrsApplicationSelect("(" + JaxrsWhiteboardConstants.JAX_RS_NAME + "=" + RESTConstants.JAX_RS_NAME + ")")
//@JSONRequired
@Path(AccessControlRessource.PATH_ACCESS_CONTROL)
// see https://docs.swagger.io/swagger-core/v2.1.12/apidocs/io/swagger/v3/oas/annotations/tags/Tag.html
@Tag(name = AccessControlRessource.PATH_ACCESS_CONTROL)
@NonNullByDefault
public class AccessControlRessource implements RESTResource {
    /** The URI path to this resource */
    public static final String PATH_ACCESS_CONTROL = "accessControl";

    /**
     * Replaces part of the URI builder by forwarded headers.
     *
     * @param uriBuilder the URI builder
     * @param httpHeaders the HTTP headers
     */
    private static void respectForwarded(final UriBuilder uriBuilder, final @Context HttpHeaders httpHeaders) {
        Optional.ofNullable(httpHeaders.getHeaderString("X-Forwarded-Host")).ifPresent(host -> {
            final int pos1 = host.indexOf("[");
            final int pos2 = host.indexOf("]");
            final String hostWithIpv6 = (pos1 >= 0 && pos2 > pos1) ? host.substring(pos1, pos2 + 1) : null;
            final String[] parts = hostWithIpv6 == null ? host.split(":") : host.substring(pos2 + 1).split(":");
            uriBuilder.host(hostWithIpv6 != null ? hostWithIpv6 : parts[0]);
            if (parts.length > 1) {
                uriBuilder.port(Integer.parseInt(parts[1]));
            }
        });
        Optional.ofNullable(httpHeaders.getHeaderString("X-Forwarded-Proto")).ifPresent(uriBuilder::scheme);
    }

    private final Logger logger = LoggerFactory.getLogger(ItemResource.class);



    private final UserRegistry userRegistry;
    private final RoleRegistry roleRegistry;
    private final GroupRegistry groupRegistry;
    private final VerifyToken verifyToken;

    @Activate
    public AccessControlRessource(final @Reference UserRegistry userRegistry,
                        final @Reference RoleRegistry roleRegistry,
                        final @Reference GroupRegistry groupRegistry, final @Reference VerifyToken verifyToken){

        this.userRegistry = userRegistry;
        this.roleRegistry = roleRegistry;
        this.groupRegistry = groupRegistry;
        this.verifyToken = verifyToken;
    }

    @GET
    @PermitAll
    @Produces(MediaType.TEXT_PLAIN)
    //@Operation(operationId = "getItems", summary = "Get all available items.", responses = {
      //      @ApiResponse(responseCode = "200", description = "OK", content = @Content(array = @ArraySchema(schema = @Schema(implementation = EnrichedItemDTO.class)))) })
    public Response getItems(final @Context UriInfo uriInfo, final @Context HttpHeaders httpHeaders) {

        Principal principal;
        try {
            principal = verifyToken.getPrincipalFromRequestContext(httpHeaders);
        } catch (IOException io) {
            principal = verifyToken.anonymousPrincipal;
        }
        System.out.println("That works!!!");
        System.out.println(principal.getName());

        return Response.ok("IT works").build();
    }

}
