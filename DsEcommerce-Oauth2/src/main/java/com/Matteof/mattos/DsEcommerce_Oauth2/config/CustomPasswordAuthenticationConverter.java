package com.Matteof.mattos.DsEcommerce_Oauth2.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Map;

public class CustomPasswordAuthenticationConverter implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {

        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);

        if (!"password".equals(grantType)) return null;

        MultiValueMap<String, String> parameters = getParameters(request);


        return null;
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
