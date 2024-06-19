package com.keycloakintegration.keycloak.dto;

import lombok.Builder;
import lombok.Data;
import org.springframework.http.HttpStatus;

@Data
@Builder
public class ExceptionInfo {
    private String message;
    private int status;
}
