package com.Matteof.mattos.DsEcommerce_Oauth2.config;

import jakarta.annotation.Nullable;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Getter
@Setter
public class MyPasswordAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    private String username;
    private String password;
    private Set<String> scopes;

    /**
     * Sub-class constructor.
     *
     * @param authorizationGrantType the authorization grant type
     * @param clientPrincipal        the authenticated client principal
     * @param additionalParameters   the additional parameters
     */
    protected MyPasswordAuthenticationToken(AuthorizationGrantType authorizationGrantType,
                                            Authentication clientPrincipal,
                                            @Nullable Map<String, Object> additionalParameters,
                                            @Nullable Set<String> scopes) {

        super(new AuthorizationGrantType("password"),
                clientPrincipal,
                additionalParameters);

        this.username = (String) additionalParameters.get("username");
        this.password = (String) additionalParameters.get("password");
        this.scopes = Collections
                .unmodifiableSet(scopes!=null ? new HashSet<>(scopes) : Collections.emptySet());

    }
}
