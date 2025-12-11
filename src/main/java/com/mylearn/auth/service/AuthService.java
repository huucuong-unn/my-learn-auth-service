package com.mylearn.auth.service;

import com.mylearn.auth.entity.User;
import com.mylearn.auth.exception.AuthException;
import com.mylearn.auth.repository.UserRepository;
import com.mylearn.common.dto.auth.LoginRequest;
import com.mylearn.common.dto.auth.TokenResponse;
import com.mylearn.common.dto.auth.UserRegistrationRequest;
import com.mylearn.common.dto.auth.UserResponse;
import com.mylearn.common.enums.UserRole;
import jakarta.transaction.Transactional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * Core business logic service for user authentication and authorization token management. For this
 * project, keeping the AuthService as a single implementation class is a common and often preferred
 * practice, especially in a microservice where the service logic is relatively contained and there
 * is only one implementation.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

  private final UserRepository userRepository;
  private final JwtService jwtService;
  private final PasswordEncoder passwordEncoder;
  private final AuthenticationManager authenticationManager;

  @Transactional
  public UserResponse register(UserRegistrationRequest request) {
    log.trace("Attempting to register new user with email: {}", request.getEmail());

    // 1. Check if user already exists
    if (userRepository.existsByEmail(request.getEmail())) {
      log.warn("Registration failed: User with email {} already exists", request.getEmail());
      throw new AuthException("Email already in use.", HttpStatus.CONFLICT);
    }

    // 2. Create and persist the User entity
    User newUser = new User();
    newUser.setEmail(request.getEmail());
    // SECURITY NOTE: ALWAYS hash the password before saving it.
    newUser.setPasswordHash(passwordEncoder.encode(request.getPassword()));
    newUser.setRole(UserRole.LEARNER); // Default role assignment

    User savedUser = userRepository.save(newUser);
    log.info("User registered successfully with ID: {}", savedUser.getId());

    // 3. Prepare response DTO (excluding password hash)
    return UserResponse.builder()
        .id(savedUser.getId())
        .email(savedUser.getEmail())
        .fullName(
            request.getFullName()) // Full name is only known during registration here; it will be
        // stored in user-service later.
        .role(savedUser.getRole())
        .build();
  }

  /**
   * Handles user login and generates JWT tokens.
   *
   * @param request DTO containing email and password.
   * @return TokenResponse DTO containing access and refresh tokens.
   * @throws AuthException if authentication fails.
   */
  public TokenResponse login(LoginRequest request) {
    log.info("Attempting to log in user with email: {}", request.getEmail());

    try {
      // 1. Authenticate using Spring Security's AuthenticationManager
      // This triggers the UserDetailsService and PasswordEncoder logic defined in SecurityConfig.
      Authentication authentication =
          authenticationManager.authenticate(
              new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

      // 2. If authentication is successful, load the full User object
      String email = authentication.getName();
      User user =
          userRepository
              .findByEmail(email)
              .orElseThrow(
                  () ->
                      new AuthException(
                          "User data not found after successful authentication.",
                          HttpStatus.NOT_FOUND));

      // 3. Generate tokens
      String accessToken = jwtService.generateAccessToken(user);
      String refreshToken = jwtService.generateRefreshToken(user);

      // 4. Persist the refresh token (or store in Redis)
      user.setRefreshToken(refreshToken);
      userRepository.save(user);

      log.info("User {} logged in successfully. Tokens issued.", user.getId());

      // 5. Build and return the response
      return TokenResponse.builder()
          .accessToken(accessToken)
          .refreshToken(refreshToken)
          // The token expiration is in milliseconds in JWTService,
          // but the response DTO expects seconds (3600000ms / 1000 = 3600s)
          .expiresIn(jwtService.getAccessTokenExpiration() / 1000)
          .build();

    } catch (org.springframework.security.core.AuthenticationException e) {
      log.warn("Login failed for email {}: Invalid credentials.", request.getEmail());
      throw new AuthException("Invalid email or password.", HttpStatus.UNAUTHORIZED);
    }
  }

  /**
   * Handles token refresh using a valid refresh token.
   *
   * @param oldRefreshToken The refresh token provided by the client.
   * @return New TokenResponse DTO.
   * @throws AuthException if the token is invalid or user is not found.
   */
  public TokenResponse refreshToken(String oldRefreshToken) {
    // 1. Validate the refresh token structure/signature
    if (!jwtService.isTokenValid(oldRefreshToken)) {
      throw new AuthException("Invalid or expired refresh token.", HttpStatus.UNAUTHORIZED);
    }

    // 2. Extract user identity from the token
    UUID userId = jwtService.extractUserId(oldRefreshToken);
    User user =
        userRepository
            .findById(userId)
            .orElseThrow(
                () ->
                    new AuthException(
                        "User not found during token refresh.", HttpStatus.NOT_FOUND));

    // 3. Check if the token matches the one stored in the database (or Redis)
    if (!oldRefreshToken.equals(user.getRefreshToken())) {
      log.warn("Refresh token mismatch for user ID: {}", userId);
      throw new AuthException("Refresh token revoked or invalid.", HttpStatus.UNAUTHORIZED);
    }

    // 4. Generate new tokens
    String newAccessToken = jwtService.generateAccessToken(user);
    String newRefreshToken = jwtService.generateRefreshToken(user);

    // 5. Update the stored refresh token
    user.setRefreshToken(newRefreshToken);
    userRepository.save(user);

    log.info("Tokens refreshed successfully for user ID: {}", userId);

    return TokenResponse.builder()
        .accessToken(newAccessToken)
        .refreshToken(newRefreshToken)
        .expiresIn(jwtService.getAccessTokenExpiration() / 1000)
        .build();
  }
}
