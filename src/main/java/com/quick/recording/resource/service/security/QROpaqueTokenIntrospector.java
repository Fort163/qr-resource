package com.quick.recording.resource.service.security;

import com.quick.recording.resource.service.enumeration.AuthProvider;
import com.quick.recording.resource.service.enumeration.Gender;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.*;
import org.springframework.http.client.support.BasicAuthenticationInterceptor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Component
public class QROpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    private Converter<String, RequestEntity<?>> requestEntityConverter;
    private RestTemplate restTemplate = new RestTemplate();
    private final ResourceServicePropertiesInterface resourceServerProperties;

    public QROpaqueTokenIntrospector(ResourceServicePropertiesInterface resourceServerProperties) throws URISyntaxException {
        this.resourceServerProperties = resourceServerProperties;
        restTemplate.getInterceptors().add(new BasicAuthenticationInterceptor(this.resourceServerProperties.getClientId(), this.resourceServerProperties.getClientSecret()));
        this.requestEntityConverter = this.defaultRequestEntityConverter();
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        RequestEntity<?> requestEntity = (RequestEntity) this.requestEntityConverter.convert(token);
        if (requestEntity == null) {
            throw new OAuth2IntrospectionException("requestEntityConverter returned a null entity");
        } else {
            ResponseEntity<Map<String, Object>> responseEntity = this.makeRequest(requestEntity);
            return this.customConvert(responseEntity.getBody());
        }
    }

    private ResponseEntity<Map<String, Object>> makeRequest(RequestEntity<?> requestEntity) {
        try {
            return this.restTemplate.exchange(requestEntity, new ParameterizedTypeReference<Map<String, Object>>() {
            });
        } catch (Exception var3) {
            throw new BadOpaqueTokenException(var3.getMessage(), var3);
        }
    }

    private Converter<String, RequestEntity<?>> defaultRequestEntityConverter() {
        return (token) -> {
            HttpHeaders headers = this.requestHeaders();
            MultiValueMap<String, String> body = this.requestBody(token);
            return new RequestEntity(body, headers, HttpMethod.POST, URI.create(this.resourceServerProperties.getIntrospectionUri()));
        };
    }

    private HttpHeaders requestHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        try {
            String username =
                    ((ServletRequestAttributes) Objects.requireNonNull(RequestContextHolder.getRequestAttributes()))
                            .getRequest().getHeader("username");
            headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
            if (Objects.isNull(username)) {
                headers.add("username", this.resourceServerProperties.getUsername());
            } else {
                headers.add("username", username);
            }
            return headers;
        }
        catch (Exception e){
            headers.add("username", this.resourceServerProperties.getUsername());
            return headers;
        }

    }

    private MultiValueMap<String, String> requestBody(String token) {
        MultiValueMap<String, String> body = new LinkedMultiValueMap();
        body.add("token", token);
        return body;
    }

    private OAuth2AuthenticatedPrincipal customConvert(Map<String, Object> claims) {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        if (claims.get("authorities") instanceof List) {
            for (Map<String, String> item : ((List<Map>) claims.get("authorities"))) {
                authorities.add(new SimpleGrantedAuthority(item.get("authority")));
            }
        }

        return QROAuth2AuthenticatedPrincipal.builder()
                .attributes(claims)
                .authorities(authorities)
                .uuid(UUID.fromString((String) claims.get("uuid")))
                .name((String) claims.get("name"))
                .fullName((String) claims.get("fullName"))
                .userpic((String) claims.get("userpic"))
                .email((String) claims.get("email"))
                .locale((String) claims.get("locale"))
                .provider(AuthProvider.valueOf((String) claims.get("provider")))
                .gender(getGender(claims.get("gender")))
                .phoneNumber((String) claims.get("phoneNumber"))
                .active((Boolean) claims.get("active"))
                .birthDay(getBirthDay(claims.get("birthDay")))
                .build();
    }

    private LocalDate getBirthDay(Object birthDay) {
        if (Objects.nonNull(birthDay)) {
            return LocalDate.parse((String) birthDay, DateTimeFormatter.ofPattern("dd.MM.yyyy"));
        }
        return null;
    }

    private Gender getGender(Object gender) {
        if (Objects.nonNull(gender)) {
            return Gender.valueOf((String) gender);
        }
        return Gender.NOT_DEFINED;
    }
}
