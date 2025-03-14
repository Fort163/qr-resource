package com.quick.recording.resource.service.security;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.http.client.support.BasicAuthenticationInterceptor;
import org.springframework.security.access.AuthorizationServiceException;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.Map;

@Component
public class SSOService {

    private RestTemplate restTemplate;
    private final ResourceServicePropertiesInterface resourceServerProperties;

    public SSOService(ResourceServicePropertiesInterface resourceServerProperties) {
        this.resourceServerProperties = resourceServerProperties;
        restTemplate = new RestTemplate();
        restTemplate.getInterceptors().add(new BasicAuthenticationInterceptor(this.resourceServerProperties.getClientId(), this.resourceServerProperties.getClientSecret()));
    }

    public SSOResult getSSOResult() throws URISyntaxException, AuthorizationServiceException {
        RequestEntity<?> requestEntity = createRequest(new URI(this.resourceServerProperties.getSsoUrl() + "oauth2/token?grant_type=client_credentials"));
        ResponseEntity<Map<String, Object>> responseEntity = this.makeRequest(requestEntity);
        if (responseEntity.hasBody()) {
            String access_token = (String) responseEntity.getBody().get("access_token");
            return new SSOResult(this.resourceServerProperties.getUsername(), access_token);
        }
        throw new AuthorizationServiceException("SSOService cant get token!");
    }

    private RequestEntity createRequest(URI uri) {
        HttpHeaders headers = this.requestHeaders();
        return new RequestEntity(headers, HttpMethod.POST, uri);
    }

    private HttpHeaders requestHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        return headers;
    }

    private ResponseEntity<Map<String, Object>> makeRequest(RequestEntity<?> requestEntity) {
        try {
            return this.restTemplate.exchange(requestEntity, new ParameterizedTypeReference<Map<String, Object>>() {
            });
        } catch (Exception var3) {
            throw new OAuth2IntrospectionException(var3.getMessage(), var3);
        }
    }

    public record SSOResult(String userName, String token) {

    }

}
