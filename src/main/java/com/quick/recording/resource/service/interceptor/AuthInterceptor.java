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
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import java.net.URISyntaxException;
import java.util.Objects;

@Component
@Log4j2
@RequiredArgsConstructor
public class AuthInterceptor implements RequestInterceptor {

    private final SSOService ssoService;
    public static final String WITH_SERVER_AUTH = "WithServerAuth";

    @Override
    public void apply(RequestTemplate requestTemplate) {
        Object attribute = Objects.requireNonNull(RequestContextHolder.getRequestAttributes())
                .getAttribute(WITH_SERVER_AUTH, RequestAttributes.SCOPE_REQUEST);
        boolean isServerAuth = Objects.nonNull(attribute) && Boolean.parseBoolean(attribute.toString());
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String tokenString = "Bearer ";
        if(!isServerAuth && Objects.nonNull(authentication) && authentication.getCredentials() instanceof OAuth2AccessToken){
            OAuth2AccessToken token = (OAuth2AccessToken)authentication.getCredentials();
            tokenString += token.getTokenValue();
        }
        else {
            try {
                SSOService.SSOResult ssoResult = ssoService.getSSOResult();
                tokenString += ssoResult.token();
                requestTemplate.header("username",ssoResult.userName());
            } catch (URISyntaxException e) {
                e.printStackTrace();
            } catch (AuthorizationServiceException e) {
                e.printStackTrace();
            }
        }
        requestTemplate.header("Authorization",tokenString);
    }

}
