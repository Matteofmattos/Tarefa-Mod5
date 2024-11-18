package com.Matteof.mattos.DsEcommerce_Oauth2.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;

@Configuration
public class AuthorizationServerConfig {

    @Autowired
    private UserDetailsService userDetailsService;

    @Bean
    @Order(2)
    public SecurityFilterChain asSecurityFilterChain(HttpSecurity http) throws Exception{

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .tokenEndpoint(tokenEndpoint -> tokenEndpoint.accessTokenRequestConverter(new CustomPasswordAuthenticationConverter())
                .authenticationProvider(
                        new CustomPasswordAuthenticationProvider(
                                authorizationService(),
                                tokenGenerator(),
                                userDetailsService,
                                passwordEncoder())));

        http.oauth2ResourceServer(oauth2ResourceServer -> oauth2ResourceServer.jwt(Customizer.withDefaults()));
        // @formatter:on
        return http.build();
    }

    private OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator() {

        NimbusJwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource());
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(tokenCustomizer()); //O customizador de token adiciona claims...
    }

    private OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {

        return context -> {
            Authentication authentication = context.getPrincipal();
            List<String> authorities = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority).toList();

            if (context.getTokenType().getValue().equals("access_token")){
                context.getClaims()
                        .claim("authorities",authorities)
                        .claim("username",authentication.getName());
            }
        };
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    private JWKSource<SecurityContext> jwkSource() {
        RSAKey privateKey = generateRsa(); // Chave privada
        JWKSet jwkSet = new JWKSet(privateKey); //Set de chaves publicas decodificadoras do Token JWT;
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    private RSAKey generateRsa() {

        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic(); // obtendo a chave publica
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate(); // obtendo chave privada

        //Entregando a chave privada vinculada à publica e gerando um UUID;
        return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
    }


    private KeyPair generateRsaKey() {      //Method gerador do par de chaves RSA

        KeyPair keyPair;

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA"); //Algoritmo gerador do par de chaves
            keyPairGenerator.initialize(2048); //Por que esse temanho ?
            keyPair = keyPairGenerator.generateKeyPair();

        } catch (Exception ex) { throw new IllegalStateException(ex); }

        return keyPair;
    }

    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
