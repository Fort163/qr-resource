package com.quick.recording.resource.service.interceptor;

import com.quick.recording.resource.service.anatation.WithServerAuth;
import com.quick.recording.resource.service.security.SSOService;
import feign.RequestInterceptor;
import feign.RequestTemplate;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.access.AuthorizationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Component;

import java.net.URISyntaxException;
import java.util.Objects;

@Component
@Log4j2
@RequiredArgsConstructor
public class AuthInterceptor implements RequestInterceptor {

    private final SSOService ssoService;

    @Override
    public void apply(RequestTemplate requestTemplate) {
        boolean isServerAuth = Objects.nonNull(requestTemplate.methodMetadata().method().getAnnotation(WithServerAuth.class));
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String tokenString = "Bearer ";
        if(!isServerAuth && Objects.nonNull(authentication) && authentication.getCredentials() instanceof OAuth2AccessToken){
            OAuth2AccessToken token = (OAuth2AccessToken)authentication.getCredentials();
            tokenString += token.getTokenValue();
        }
        else {
            try {
                tokenString += ssoService.getToken();
            } catch (URISyntaxException e) {
                e.printStackTrace();
            } catch (AuthorizationServiceException e) {
                e.printStackTrace();
            }
        }
        requestTemplate.header("Authorization",tokenString);
    }

}
