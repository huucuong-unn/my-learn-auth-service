package com.mylearn.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Configuration for setting up WebClient beans for inter-service communication.
 */
@Configuration
public class WebClientConfig {

  @Value("${app.services.user-service-url}")
  private String userServiceUrl;

  @Bean
  public WebClient userServiceWebClient() {
    return WebClient.builder()
        .baseUrl(userServiceUrl)
        .build();
  }
}
