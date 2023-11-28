package com.quick.recording.resource.service.security;

public interface ResourceServicePropertiesInterface {

    String getUsername();

    String getClientId();

    String getClientSecret();

    String getIntrospectionUri();

    String getSsoUrl();

    Boolean getCustomAuth();

}
