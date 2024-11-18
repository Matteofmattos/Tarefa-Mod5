package com.Matteof.mattos.DsEcommerce_Oauth2.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.*;

public class CustomPasswordAuthenticationConverter implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {

        //Obtendo o tipo de concessão.
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);

        if (!"password".equals(grantType)) return null;


        //Obtendo os parâmetros...
        MultiValueMap<String, String> parameters = getParameters(request);


        //Obtendo o scope...(opcional no MyOAuth2authorizationToken)
        String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
        if (StringUtils.hasText(scope) &&
                parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        // username (REQUIRED)
        String username = parameters.getFirst(OAuth2ParameterNames.USERNAME);
        if (!StringUtils.hasText(username) ||
                parameters.get(OAuth2ParameterNames.USERNAME).size() != 1) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        // password (REQUIRED)
        String password = parameters.getFirst(OAuth2ParameterNames.PASSWORD);
        if (!StringUtils.hasText(password) ||
                parameters.get(OAuth2ParameterNames.PASSWORD).size() != 1) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }


        //Criando o Set de escopos;
        Set<String> requestedScopes = null;
        if (StringUtils.hasText(scope)) {
            requestedScopes = new HashSet<>(Arrays.asList(StringUtils
                    .delimitedListToStringArray(scope, " ")));
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) &&
                    !key.equals(OAuth2ParameterNames.SCOPE)) {
                additionalParameters.put(key, value.getFirst());
            }
        });

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return new MyPasswordAuthenticationToken(authentication, additionalParameters, requestedScopes);
    }

    private MultiValueMap<String, String> getParameters(HttpServletRequest request) {

        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String,String> parameters = new LinkedMultiValueMap<>(parameterMap.size());

        for (Map.Entry<String, String[]> parameter : parameterMap.entrySet()) {

            String key = parameter.getKey();
            String[] values = parameter.getValue();

            if (values.length > 0)
                for (String value : values) parameters.add(key, value);
        }
        return parameters;
    }
}
