package com.keycloakintegration.keycloak.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class APIResponse {
    private String message;
    private int status;
}
