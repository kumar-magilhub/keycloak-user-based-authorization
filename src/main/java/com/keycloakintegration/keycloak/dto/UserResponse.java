package com.keycloakintegration.keycloak.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Builder
@Data
public class UserResponse {
    private String userId;
    private String userName;
    private String firstName;
    private String lastName;
    private List<UserPermissionResponse> userPermissionResponses;
}
