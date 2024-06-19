package com.keycloakintegration.keycloak.dto;

import lombok.Data;

import java.util.List;

@Data
public class UserRequest {
    private String userName;
    private String email;
    private String firstName;
    private String lastName;
    private String password;
    private String role;
    private List<UserAccessInfo> accessInfos;
}
