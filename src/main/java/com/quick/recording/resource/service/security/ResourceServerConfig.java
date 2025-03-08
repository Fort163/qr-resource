package com.quick.recording.resource.service.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.util.Objects;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
@EnableMethodSecurity
public class ResourceServerConfig {

    private final QROpaqueTokenIntrospector qrOpaqueTokenIntrospector;
    private final ResourceServicePropertiesInterface resourceServerProperties;
    private final AccessDeniedHandler accessDeniedHandler;
    private final AuthenticationEntryPoint authenticationEntryPoint;

    @Bean
    public SecurityFilterChain securityApiFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/**").sessionManagement(configurer -> configurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(customizer -> {
                    if(Objects.isNull(resourceServerProperties.getCustomAuth()) || !resourceServerProperties.getCustomAuth()) {
                        customizer.anyRequest().authenticated();
                    }
                    else {
                        customizer.anyRequest().permitAll();
                    }
                });
        http.oauth2ResourceServer(config -> {
            config.opaqueToken(token -> {
                token.introspector(qrOpaqueTokenIntrospector);
            });
            config.authenticationEntryPoint(authenticationEntryPoint);
            config.accessDeniedHandler(accessDeniedHandler);
        });
        return http.build();
    }

}
