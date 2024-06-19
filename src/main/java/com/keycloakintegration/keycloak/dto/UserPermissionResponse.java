package com.keycloakintegration.keycloak.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class UserPermissionResponse {
    @JsonProperty("resource_id")
    private String resourceId;

    @JsonProperty("rsname")
    private String resourceName;
}
