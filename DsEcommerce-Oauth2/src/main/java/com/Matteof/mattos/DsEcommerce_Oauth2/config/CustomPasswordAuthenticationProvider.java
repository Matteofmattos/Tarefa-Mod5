package com.Matteof.mattos.DsEcommerce_Oauth2.config;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class CustomPasswordAuthenticationProvider implements AuthenticationProvider {

    public CustomPasswordAuthenticationProvider(Object authorizationService, Object tokenGenerator, Object p2, Object passwordEncoder) {
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return false;
    }
}
