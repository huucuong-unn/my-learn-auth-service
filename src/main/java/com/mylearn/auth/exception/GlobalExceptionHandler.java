package com.mylearn.auth.exception;

import java.util.Objects;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;

/**
 * Global Exception Handler to catch custom and common exceptions and return standardized error
 * responses.
 */
@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

  /** Handles custom AuthException errors and maps them to the appropriate HTTP status code. */
  @ExceptionHandler(AuthException.class)
  public ResponseEntity<?> handleAuthException(AuthException ex, WebRequest request) {
    HttpStatus status =
        Objects.nonNull(ex.getStatus()) ? ex.getStatus() : HttpStatus.INTERNAL_SERVER_ERROR;
    log.warn("AuthException caught ({}): {}", status.value(), ex.getMessage());

    ErrorResponse errorResponse =
        new ErrorResponse(status.value(), ex.getMessage(), request.getDescription(false));
    return new ResponseEntity<>(errorResponse, status);
  }

  private record ErrorResponse(int status, String message, String details) {}
}
