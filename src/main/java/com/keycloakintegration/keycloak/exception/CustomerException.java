package com.keycloakintegration.keycloak.exception;

import org.springframework.http.HttpStatusCode;
import org.springframework.web.server.ResponseStatusException;

public class CustomerException extends ResponseStatusException {

    public CustomerException(HttpStatusCode status, String reason) {
        super(status, reason);
    }
}
