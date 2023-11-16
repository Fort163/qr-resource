package com.quick.recording.resource.service.security;

import com.netflix.discovery.EurekaClient;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.log4j.Log4j2;
import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.Objects;

@ConfigurationProperties(prefix = "spring.security.oauth2.resourceserver.opaquetoken")
@Setter
@Getter
@Configuration
@Log4j2
public class ResourceServerProperties {

    @Value("${spring.application.name}")
    private String username;
    private String clientId;
    private String clientSecret;
    private String introspectionUri;
    private String ssoUrl;
    private Boolean customAuth;

    @Autowired
    public ResourceServerProperties(EurekaClient discoveryClient) {
        String homePageUrl = discoveryClient.getApplications().getRegisteredApplications("AUTH-SERVICE").getInstancesAsIsFromEureka().stream().findFirst().get().getHomePageUrl();
        ssoUrl = homePageUrl;
        introspectionUri = homePageUrl+"oauth2/token-info";
    }

    @PostConstruct
    private void checkParams(){
        checkParam(clientId,"clientId");
        checkParam(clientSecret,"clientSecret");
        checkParam(username,"username");
        checkParam(customAuth,"customAuth");
    }

    private void checkParam(Boolean param, String name){
        if(Objects.isNull(param)){
            log.warn("\n\t\t\tParam spring.security.oauth2.resourceserver.opaquetoken : "+name+" not set resource use default settings - anyRequest().authenticated()!\n");
        }
    }

    private void checkParam(String param, String name){
        if(Strings.isEmpty(param)){
            log.error("\n\t\t\tParam spring.security.oauth2.resourceserver.opaquetoken :"+name+" not set resource server not work!\n");
        }
    }

}
