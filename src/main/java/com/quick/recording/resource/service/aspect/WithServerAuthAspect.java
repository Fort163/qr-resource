package com.quick.recording.resource.service.aspect;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.After;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;

import java.util.Objects;

import static com.quick.recording.resource.service.interceptor.AuthInterceptor.WITH_SERVER_AUTH;
import static org.springframework.web.context.request.RequestAttributes.SCOPE_REQUEST;

@Slf4j
@Aspect
@Component
public class WithServerAuthAspect {

    @Before("@annotation(com.quick.recording.resource.service.anatation.WithServerAuth)")
    public void beforeMethod(JoinPoint jp) {
        Objects.requireNonNull(RequestContextHolder.getRequestAttributes()).setAttribute(WITH_SERVER_AUTH, true, SCOPE_REQUEST);
    }

    @After("@annotation(com.quick.recording.resource.service.anatation.WithServerAuth)")
    public void afterMethod(JoinPoint jp) {
        Objects.requireNonNull(RequestContextHolder.getRequestAttributes()).removeAttribute(WITH_SERVER_AUTH, SCOPE_REQUEST);
    }

}
