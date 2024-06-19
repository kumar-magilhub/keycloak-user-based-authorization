package com.keycloakintegration.keycloak.controller;

import com.keycloakintegration.keycloak.dto.APIResponse;
import com.keycloakintegration.keycloak.dto.UserRequest;
import com.keycloakintegration.keycloak.dto.UserResponse;
import com.keycloakintegration.keycloak.service.KeycloakService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/keycloak")
public class KeycloakController {


    private final KeycloakService keycloakService;

    public KeycloakController(KeycloakService keycloakService) {
        this.keycloakService = keycloakService;
    }

    @PostMapping("/")
    public APIResponse creatUser(@RequestBody UserRequest userRequest) {
        return keycloakService.createUser(userRequest);
    }

    @GetMapping("/users/{userId}")
    public UserResponse fetchUserInfo(@PathVariable(value = "userId") String userId) {
        return keycloakService.getUserInfoByUserId(userId);
    }
}
