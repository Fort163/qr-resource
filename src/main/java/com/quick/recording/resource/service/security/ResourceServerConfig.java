package com.quick.recording.resource.service.security;

import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Objects;

@Configuration
@AllArgsConstructor
@EnableWebSecurity
@EnableMethodSecurity
public class ResourceServerConfig {

    private final QROpaqueTokenIntrospector qrOpaqueTokenIntrospector;
    private final ResourceServicePropertiesInterface resourceServerProperties;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.sessionManagement(configurer -> configurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(customizer -> {
                    if(Objects.isNull(resourceServerProperties.getCustomAuth()) || !resourceServerProperties.getCustomAuth()) {
                        customizer.anyRequest().authenticated();
                    }
                    else {
                        customizer.anyRequest().permitAll();
                    }
                });
        http.oauth2ResourceServer(config -> {
            config.opaqueToken().introspector(qrOpaqueTokenIntrospector);
        });
        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::opaqueToken);
        return http.build();
    }

}
