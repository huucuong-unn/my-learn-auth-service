package com.mylearn.auth.exception;

import org.springframework.http.HttpStatus;

/**
 * Custom exception for controlled authentication errors. This helps map internal errors to specific
 * HTTP status codes.
 */
public class AuthException extends RuntimeException {

  private final HttpStatus status;

  public AuthException(String message, HttpStatus status) {
    super(message);
    this.status = status;
  }

  public HttpStatus getStatus() {
    return status;
  }
}
