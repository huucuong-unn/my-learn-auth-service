package com.mylearn.auth.utils;

public class AuthConstants {

  // Authorization API endpoint mappings
  public static final String AUTHORIZATION_REQUEST_MAPPING = "/api/v1/auth";
  public static final String AUTHORIZATION_REGISTER_REQUEST_MAPPING =
      AUTHORIZATION_REQUEST_MAPPING + "/register";
  public static final String AUTHORIZATION_LOGIN_REQUEST_MAPPING =
      AUTHORIZATION_REQUEST_MAPPING + "/login";
  public static final String AUTHORIZATION_REFRESH_REQUEST_MAPPING =
      AUTHORIZATION_REQUEST_MAPPING + "/refresh";
  public static final String AUTHORIZATION_VALIDATE_REQUEST_MAPPING =
      AUTHORIZATION_REQUEST_MAPPING + "/validate";

  // Bearer token prefix
  public static final String BEARER_PREFIX = "Bearer ";
}
