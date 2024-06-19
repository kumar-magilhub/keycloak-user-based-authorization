package com.keycloakintegration.keycloak.dto;

import lombok.Data;

import java.util.List;

@Data
public class PermissionsResponse {
    private List<UserPermissionResponse> permissions;
}
