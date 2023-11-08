package com.quick.recording.resource.service.security;

import com.quick.recording.resource.service.enumeration.AuthProvider;
import com.quick.recording.resource.service.enumeration.Gender;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.*;
import org.springframework.http.client.support.BasicAuthenticationInterceptor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.LocalDate;
import java.util.*;

@Component
public class QROpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    private Converter<String, RequestEntity<?>> requestEntityConverter;
    private RestTemplate restTemplate = new RestTemplate();
    private final ResourceServerProperties resourceServerProperties;

    public QROpaqueTokenIntrospector(ResourceServerProperties resourceServerProperties) throws URISyntaxException {
        this.resourceServerProperties = resourceServerProperties;
        restTemplate.getInterceptors().add(new BasicAuthenticationInterceptor(this.resourceServerProperties.getClientId(), this.resourceServerProperties.getClientSecret()));
        this.requestEntityConverter = this.defaultRequestEntityConverter(new URI(this.resourceServerProperties.getIntrospectionUri()));
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        RequestEntity<?> requestEntity = (RequestEntity)this.requestEntityConverter.convert(token);
        if (requestEntity == null) {
            throw new OAuth2IntrospectionException("requestEntityConverter returned a null entity");
        } else {
            ResponseEntity<Map<String, Object>> responseEntity = this.makeRequest(requestEntity);
            if(Objects.isNull(responseEntity.getBody())){
                throw new OAuth2IntrospectionException("SSO service blocked the token");
            }
            return this.customConvert(responseEntity.getBody());
        }
    }

    private ResponseEntity<Map<String, Object>> makeRequest(RequestEntity<?> requestEntity) {
        try {
            return this.restTemplate.exchange(requestEntity, new ParameterizedTypeReference<Map<String, Object>>() {
            });
        } catch (Exception var3) {
            throw new OAuth2IntrospectionException(var3.getMessage(), var3);
        }
    }

    private Converter<String, RequestEntity<?>> defaultRequestEntityConverter(URI introspectionUri) {
        return (token) -> {
            HttpHeaders headers;
            if(token.contains("--0--")){
                String[] split = token.split("--0--");
                token = split[1];
                headers = this.requestHeaders(split[0]);
            }
            else {
                headers = this.requestHeaders();
            }
            MultiValueMap<String, String> body = this.requestBody(token);
            return new RequestEntity(body, headers, HttpMethod.POST, introspectionUri);
        };
    }

    private HttpHeaders requestHeaders(){
        return this.requestHeaders(null);
    }

    private HttpHeaders requestHeaders(String username) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        if(Objects.isNull(username)) {
            headers.add("username", this.resourceServerProperties.getUsername());
        }
        else {
            headers.add("username", username);
        }
        return headers;
    }

    private MultiValueMap<String, String> requestBody(String token) {
        MultiValueMap<String, String> body = new LinkedMultiValueMap();
        body.add("token", token);
        return body;
    }

    private OAuth2AuthenticatedPrincipal customConvert(Map<String, Object> claims) {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        if(claims.get("authorities") instanceof List){
            for(Map<String,String> item : ((List<Map>)claims.get("authorities"))){
                authorities.add(new SimpleGrantedAuthority(item.get("authority")));
            }
        }

        return QROAuth2AuthenticatedPrincipal.builder()
                .attributes(claims)
                .authorities(authorities)
                .name((String)claims.get("name"))
                .fullName((String)claims.get("fullName"))
                .userpic((String)claims.get("userpic"))
                .email((String)claims.get("email"))
                .locale((String)claims.get("locale"))
                .provider(AuthProvider.valueOf((String)claims.get("provider")))
                .gender(Gender.valueOf((String)claims.get("gender")))
                .phoneNumber((String)claims.get("phoneNumber"))
                .active((Boolean) claims.get("active"))
                .birthDay(LocalDate.parse((String)claims.get("birthDay")))
                .build();
    }
}
