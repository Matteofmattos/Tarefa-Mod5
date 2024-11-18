package com.Matteof.mattos.DsEcommerce_Oauth2.config;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;

import java.util.Set;
import java.util.stream.Collectors;

public class CustomPasswordAuthenticationProvider implements AuthenticationProvider {

    UserDetailsService userDetailsService;

    BCryptPasswordEncoder passwordEncoder;

    public CustomPasswordAuthenticationProvider(UserDetailsService userDetailsService, BCryptPasswordEncoder passwordEncoder) {

        Assert.notNull(userDetailsService, "UserDetailsService cannot be null");
        Assert.notNull(passwordEncoder, "PasswordEncoder cannot be null");

        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        MyPasswordAuthenticationToken passwordAuthenticationToken = (MyPasswordAuthenticationToken) authentication;
        String username = passwordAuthenticationToken.getUsername();
        String password = passwordAuthenticationToken.getPassword();
        UserDetails userDetails = null;

        OAuth2ClientAuthenticationToken oauth2AuthenticationToken =
                getAuthenticatedClientElseThrowInvalidClient(authentication);

        RegisteredClient registeredClient = oauth2AuthenticationToken.getRegisteredClient();

        try {
            userDetails = userDetailsService.loadUserByUsername(username);
        } catch (UsernameNotFoundException e) {
            throw new OAuth2AuthenticationException("# Invalid credentials!");
        }

        if (passwordEncoder.matches(passwordEncoder.encode(password),userDetails.getPassword())){
            throw new OAuth2AuthenticationException("# Invalid credentials!");
        }

        Set<String> authorizedScopes = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(scope -> registeredClient.getScopes().contains(scope))
                .collect(Collectors.toSet());


        //------------- Criando um novo ContextHolder ----------------
        OAuth2ClientAuthenticationToken oAuth2ClientAuthenticationToken = (OAuth2ClientAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        CustomUserAuthorities customUserAuthorities = new CustomUserAuthorities(username, userDetails.getAuthorities());
        oauth2AuthenticationToken.setDetails(customUserAuthorities);

        return new OAuth2AccessTokenAuthenticationToken(user, clientPrincipal, accessToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return MyPasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {

        OAuth2ClientAuthenticationToken principal = null;

        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {

            principal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
            if (principal!=null && principal.isAuthenticated()){
                return principal;
            }
        }

        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }
}
