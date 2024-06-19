package com.keycloakintegration.keycloak.dto;

import lombok.Data;

import java.util.Set;

@Data
public class UserAccessInfo {
    private String moduleName;
    private Set<String> urls;
}
