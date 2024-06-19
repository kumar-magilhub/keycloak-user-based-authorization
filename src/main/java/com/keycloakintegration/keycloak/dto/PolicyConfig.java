package com.keycloakintegration.keycloak.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class PolicyConfig {
    private String id;
    private boolean required;
}
