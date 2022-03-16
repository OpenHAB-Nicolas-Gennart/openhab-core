package org.openhab.core.io.rest.auth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.time.Duration;
import java.util.Base64;
import java.util.Random;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.SecurityContext;

import org.eclipse.jdt.annotation.Nullable;
import org.openhab.core.auth.*;
import org.openhab.core.io.rest.auth.internal.*;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component(immediate = true, service = VerifyToken.class)
public class VerifyToken {

    private final Logger logger = LoggerFactory.getLogger(VerifyToken.class);

    private static final String ALT_AUTH_HEADER = "X-OPENHAB-TOKEN";

    public String test = "IT WORKS, THE PROB IS THE VARIABLE HttpHeaders";

    private boolean allowBasicAuth = false;
    private Long cacheExpiration = 6L;
    private static final byte[] RANDOM_BYTES = new byte[32];
    private static final String API_TOKEN_PREFIX = "oh.";

    public final AnonymousPrincipal anonymousPrincipal = new AnonymousPrincipal();
    private ExpiringUserSecurityContextCache authCache = new ExpiringUserSecurityContextCache(
            Duration.ofHours(cacheExpiration).toMillis());

    private final UserRegistry userRegistry;
    private final JwtHelper jwtHelper;

    @Activate
    public VerifyToken(@Reference JwtHelper jwtHelper, @Reference UserRegistry userRegistry) {
        this.userRegistry = userRegistry;
        this.jwtHelper = jwtHelper;
        new Random().nextBytes(RANDOM_BYTES);
    }

    private @Nullable String getCacheKey(String credentials) {
        if (cacheExpiration == 0) {
            // caching is disabled
            return null;
        }
        try {
            final MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(RANDOM_BYTES);
            return new String(md.digest(credentials.getBytes()));
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is available for all java distributions so this code will actually never run
            // If it does we'll just flood the cache with random values
            logger.warn("SHA-256 is not available. Cache for basic auth disabled!");
            return null;
        }
    }

    public SecurityContext authenticateBearerToken(String token) throws AuthenticationException {
        if (token.startsWith(API_TOKEN_PREFIX)) {
            UserApiTokenCredentials credentials = new UserApiTokenCredentials(token);
            Authentication auth = userRegistry.authenticate(credentials);
            User user = userRegistry.get(auth.getUsername());
            if (user == null) {
                throw new AuthenticationException("User not found in registry");
            }
            return new UserSecurityContext(user, auth, "ApiToken");
        } else {
            Authentication auth = jwtHelper.verifyAndParseJwtAccessToken(token);
            return new JwtSecurityContext(auth);
        }
    }

    public SecurityContext authenticateBasicAuth(String credentialString) throws AuthenticationException {
        final String cacheKey = getCacheKey(credentialString);
        if (cacheKey != null) {
            final UserSecurityContext cachedValue = authCache.get(cacheKey);
            if (cachedValue != null) {
                return cachedValue;
            }
        }

        String[] decodedCredentials = new String(Base64.getDecoder().decode(credentialString), StandardCharsets.UTF_8)
                .split(":");
        if (decodedCredentials.length != 2) {
            throw new AuthenticationException("Invalid Basic authentication credential format");
        }

        UsernamePasswordCredentials credentials = new UsernamePasswordCredentials(decodedCredentials[0],
                decodedCredentials[1]);
        Authentication auth = userRegistry.authenticate(credentials);
        User user = userRegistry.get(auth.getUsername());
        if (user == null) {
            throw new AuthenticationException("User not found in registry");
        }

        UserSecurityContext context = new UserSecurityContext(user, auth, "Basic");

        if (cacheKey != null) {
            authCache.put(cacheKey, context);
        }

        return context;
    }

    /**
     * Verify the token of the request and return the user (Principal) of the request.
     *
     * @param httpHeaders The request done by the client
     * @return If the token is incorrect or the authentication failed return an AnonymousPrincipal, otherwise return the
     *         Principal.
     * @throws IOException
     */
    public Principal getPrincipalFromRequestContext(@Nullable HttpHeaders httpHeaders) throws IOException {
        if (httpHeaders != null) {
            try {
                String altTokenHeader = httpHeaders.getHeaderString(ALT_AUTH_HEADER);
                SecurityContext securityContext = null;
                if (altTokenHeader != null) {
                    securityContext = authenticateBearerToken(altTokenHeader);
                    return securityContext.getUserPrincipal();
                }
                String authHeader = httpHeaders.getHeaderString(HttpHeaders.AUTHORIZATION);
                if (authHeader != null) {
                    String[] authParts = authHeader.split(" ");
                    if (authParts.length == 2) {
                        String authType = authParts[0];
                        String authValue = authParts[1];
                        if ("Bearer".equalsIgnoreCase(authType)) {
                            securityContext = authenticateBearerToken(authValue);
                            return securityContext.getUserPrincipal();
                        } else if ("Basic".equalsIgnoreCase(authType)) {
                            String[] decodedCredentials = new String(Base64.getDecoder().decode(authValue), "UTF-8")
                                    .split(":");
                            if (decodedCredentials.length > 2) {
                                throw new AuthenticationException("Invalid Basic authentication credential format");
                            }
                            switch (decodedCredentials.length) {
                                case 1:
                                    securityContext = authenticateBearerToken(decodedCredentials[0]);
                                    break;
                                case 2:
                                    if (!allowBasicAuth) {
                                        throw new AuthenticationException(
                                                "Basic authentication with username/password is not allowed");
                                    }
                                    securityContext = authenticateBasicAuth(authValue);
                            }
                            return securityContext.getUserPrincipal();
                        }
                    }
                }
            } catch (AuthenticationException e) {
                logger.warn("Unauthorized API request: {}", e.getMessage());
                return this.anonymousPrincipal;
            }
        }
        return this.anonymousPrincipal;
    }

    private class AnonymousPrincipal implements Principal {
        private final String name = "user";

        @Override
        public String getName() {
            return name;
        }
    }
}
