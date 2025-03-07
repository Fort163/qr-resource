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
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.List;

@Component
@RequiredArgsConstructor
public class QRAccessDeniedHandler implements AccessDeniedHandler {

    @Value("${spring.application.name}")
    private String serviceName;
    private final MappingJackson2HttpMessageConverter mappingJackson2HttpMessageConverter;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        String message = accessDeniedException.getMessage() + " - " + request.getServletPath();
        ApiError build = ApiError.builder().message(message).service(serviceName).build();
        response.setStatus(HttpStatus.FORBIDDEN.value());
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
        private QRAccessDeniedHandler.ApiError parentError;
    }

}
