package com.quick.recording.resource.service.security;

import com.quick.recording.resource.service.enumeration.AuthProvider;
import com.quick.recording.resource.service.enumeration.Gender;
import lombok.Builder;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;

import java.time.LocalDate;
import java.util.Collection;
import java.util.Map;
import java.util.UUID;

@Getter
@Builder
public class QROAuth2AuthenticatedPrincipal implements OAuth2AuthenticatedPrincipal {

    private Collection<? extends GrantedAuthority> authorities;
    private Map<String, Object> attributes;
    private UUID uuid;
    private String name;
    private String fullName;
    private String userpic;
    private String email;
    private String locale;
    private AuthProvider provider;
    private Gender gender;
    private String phoneNumber;
    private LocalDate birthDay;
    private Boolean active;

}
