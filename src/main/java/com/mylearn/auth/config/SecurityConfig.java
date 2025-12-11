package com.mylearn.auth.config;

import static com.mylearn.auth.utils.AuthConstants.*;

import com.mylearn.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/** Main Spring Security configuration class. */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

  private final UserRepository userRepository;

  /**
   * Defines the security filter chain for HTTP requests. We disable CSRF since we are using
   * stateless JWT authentication. We permit all requests to the /api/v1/auth/* endpoints as they
   * handle login/registration.
   */
  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.csrf(AbstractHttpConfigurer::disable) // Disable CSRF for stateless APIs
        .authorizeHttpRequests(
            auth ->
                auth
                    // Public endpoints for registration and login
                    .requestMatchers(
                        AUTHORIZATION_REGISTER_REQUEST_MAPPING,
                        AUTHORIZATION_LOGIN_REQUEST_MAPPING,
                        AUTHORIZATION_REFRESH_REQUEST_MAPPING,
                        AUTHORIZATION_VALIDATE_REQUEST_MAPPING)
                    .permitAll()
                    // All other requests require authentication (though this service is mostly open
                    // for JWT tasks)
                    .anyRequest()
                    .authenticated());

    return http.build();
  }

  /**
   * Creates the AuthenticationProvider, which utilizes the UserDetailsService and PasswordEncoder
   * to perform the actual authentication during the login process.
   */
  @Bean
  public UserDetailsService userDetailsService() {
    return email ->
        userRepository
            .findByEmail(email)
            .map(
                user ->
                    org.springframework.security.core.userdetails.User.builder()
                        .username(user.getEmail())
                        .password(user.getPasswordHash())
                        // Spring Security expects roles as a comma-separated list of strings
                        .roles(user.getRole().name())
                        .build())
            .orElseThrow(
                () -> new UsernameNotFoundException("User not found with email: " + email));
  }

  /**
   * Defines the PasswordEncoder bean, using BCrypt, which is standard practice for securely hashing
   * passwords.
   */
  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  /**
   * Creates the AuthenticationProvider, which utilizes the UserDetailsService and PasswordEncoder
   * to perform the actual authentication during the login process.
   */
  @Bean
  public AuthenticationProvider authenticationProvider() {
    DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(userDetailsService());
    authProvider.setPasswordEncoder(passwordEncoder());

    return authProvider;
  }

  /**
   * Exposes the AuthenticationManager needed by the AuthService to authenticate users
   * programmatically.
   */
  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
      throws Exception {
    return config.getAuthenticationManager();
  }
}
