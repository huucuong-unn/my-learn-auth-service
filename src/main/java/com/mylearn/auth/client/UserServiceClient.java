package com.mylearn.auth.client;

import com.mylearn.auth.exception.UserServiceClientException;
import com.mylearn.common.dto.user.InternalProfileCreationRequest;
import com.mylearn.common.dto.user.UserProfileResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * Client service responsible for making synchronous HTTP calls from auth-service to user-service.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceClient {

  private final WebClient userServiceWebClient;

  /**
   * Calls the internal user-service endpoint to create the initial user profile immediately after
   * registration in the auth-service.
   */
  public UserProfileResponse createProfile(InternalProfileCreationRequest request) {
    log.info("Sending profile creation request to user-service for user ID: {}",
        request.getUserId());

    // This is a synchronous call (using block()) in a traditional Spring MVC controller,
    // which is generally acceptable for mandatory service-to-service orchestration steps.
    // For better resiliency, consider making this call asynchronous or using Kafka events
    // (which you plan to implement later for notifications).
    try {

      return userServiceWebClient.post()
          .uri("/internal/profiles")
          .contentType(MediaType.APPLICATION_JSON)
          .body(BodyInserters.fromValue(request))
          .retrieve()
          // Handle Http error status codes (e.g 4xx, 5xx) appropriately
          .onStatus(status -> status.is4xxClientError() || status.is5xxServerError(),
              clientResponse -> clientResponse.bodyToMono(String.class)
                  .flatMap(errorBody -> {
                    log.error("User service error ({}): {}", clientResponse.statusCode(),
                        errorBody);
                    return Mono.error(new UserServiceClientException(
                        "Failed to create profile " + clientResponse.statusCode() + " - "
                            + errorBody
                    ));
                  })
          )
          .bodyToMono(UserProfileResponse.class)
          .block(); // Block until the response is received

    } catch (Exception e) {
      log.error("Communication error with user-service: {}", e.getMessage());
      throw new UserServiceClientException("Error communicating with user-service.", e);
    }
  }
}
