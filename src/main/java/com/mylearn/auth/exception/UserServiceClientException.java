package com.mylearn.auth.exception;

/**
 * Custom exception for controlled errors during communication with the user-service.
 */
public class UserServiceClientException extends RuntimeException{

  public UserServiceClientException(String message) {
    super(message);
  }

  public UserServiceClientException(String message, Throwable cause) {
    super(message, cause);
  }
}
