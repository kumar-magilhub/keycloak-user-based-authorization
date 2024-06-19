package com.keycloakintegration.user.exception;

import com.keycloakintegration.keycloak.dto.ExceptionInfo;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
@Slf4j
public class UserExceptionHandler {


    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleGlobalException(Exception exception) {
        log.info("Entere");
        return null;
    }
}
