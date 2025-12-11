package com.mylearn.auth.controller;

import static com.mylearn.auth.utils.AuthConstants.*;

import com.mylearn.auth.service.AuthService;
import com.mylearn.auth.service.JwtService;
import com.mylearn.common.dto.auth.*;
import com.mylearn.common.enums.UserRole;
import java.util.Objects;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequiredArgsConstructor
public class AuthController {

  private final AuthService authService;
  private final JwtService jwtService; // Used only for internal validation endpoint

  /** POST /api/v1/auth/register Creates a new user account. */
  @PostMapping(AUTHORIZATION_REGISTER_REQUEST_MAPPING)
  public ResponseEntity<UserResponse> register(@RequestBody UserRegistrationRequest request) {
    UserResponse userResponse = authService.register(request);
    return new ResponseEntity<>(userResponse, HttpStatus.CREATED);
  }

  /** POST /api/v1/auth/login Authenticates user and issues JWTs. */
  @PostMapping(AUTHORIZATION_LOGIN_REQUEST_MAPPING)
  public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest request) {
    TokenResponse tokenResponse = authService.login(request);
    return ResponseEntity.ok(tokenResponse);
  }

  /** POST /api/v1/auth/refresh Issues a new access token using a valid refresh token. */
  @PostMapping(AUTHORIZATION_REFRESH_REQUEST_MAPPING)
  public ResponseEntity<TokenResponse> refresh(@RequestBody TokenResponse request) {
    TokenResponse placeholderResponse = authService.refreshToken(request.getRefreshToken());
    return ResponseEntity.ok(placeholderResponse);
  }

  /**
   * GET /api/v1/auth/validate Internal endpoint for the API Gateway to validate a JWT and return
   * user context. This endpoint is crucial for service-to-service communication.
   */
  @GetMapping(AUTHORIZATION_VALIDATE_REQUEST_MAPPING)
  public ResponseEntity<AuthValidationResponse> validate(
      @RequestHeader("Authorization") String authorizationHeader) {

    // 1. Extract the JWT from the "Bearer <token>" header format
    if (Objects.isNull(authorizationHeader) || !authorizationHeader.startsWith(BEARER_PREFIX)) {
      log.warn("Authorization header is missing or malformed");
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    String token = authorizationHeader.substring(BEARER_PREFIX.length());

    // 2. Validate the token and extract claims
    if (!jwtService.isTokenValid(token)) {
      return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
    }

    UUID userId = jwtService.extractUserId(token);
    UserRole role = jwtService.extractUserRole(token);

    // 3. Build and return the validation response
    return ResponseEntity.ok(AuthValidationResponse.builder().userId(userId).role(role).build());
  }
}
