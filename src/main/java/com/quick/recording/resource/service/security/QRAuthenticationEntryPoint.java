package com.quick.recording.resource.service.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.List;

@Component
@RequiredArgsConstructor
public class QRAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Value("${spring.application.name}")
    private String serviceName;
    private final MappingJackson2HttpMessageConverter mappingJackson2HttpMessageConverter;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        String message = authException.getMessage() + " - " + request.getServletPath();
        ApiError build = ApiError.builder().message(message).service(serviceName).build();
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
        mappingJackson2HttpMessageConverter.write(build, null, httpResponse);
    }

    @Data
    @Builder
    static class ApiError {
        private String service;
        private String message;
        private String debugMessage;
        private List<String> errors;
        private ApiError parentError;
    }
}
