package com.keycloakintegration.keycloak.exception;

import com.keycloakintegration.keycloak.dto.ExceptionInfo;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class KeycloakExceptionHandler {

    @ExceptionHandler(CustomerException.class)
    public ResponseEntity<?> handleCustomerException(CustomerException customerException) {
        ExceptionInfo exceptionInfo = ExceptionInfo
                .builder()
                .message(customerException.getReason())
                .status(customerException.getStatusCode().value())
                .build();
        return ResponseEntity.status(exceptionInfo.getStatus()).body(exceptionInfo);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleGlobalException(Exception exception) {
        int httpStatus = exception.getMessage().contains("Unauthorized") ?
                HttpStatus.UNAUTHORIZED.value() : HttpStatus.INTERNAL_SERVER_ERROR.value();
        String message = (httpStatus == HttpStatus.UNAUTHORIZED.value()) ? "Access Denied" :
                "Something went wrong";
        ExceptionInfo exceptionInfo = ExceptionInfo
                .builder()
                .message(message)
                .status(httpStatus)
                .build();
        return ResponseEntity.status(exceptionInfo.getStatus()).body(exceptionInfo);
    }
}
