package com.mylearn.auth.service;

import com.mylearn.auth.entity.User;
import com.mylearn.common.enums.UserRole;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/** Service for generating, validating, and extracting information from Json Web Tokens (JWT). */
@Service
public class JwtService {

  // IMPORTANT: In a real application, this should be a very long, randomly generated secret
  // stored securely outside the source code (e.g., Kubernetes Secret or AWS Secrets Manager).
  // It is loaded from application.yml via @Value.
  private final String CLAIMS_USER_ID = "userId";
  private final String CLAIMS_ROLE = "role";

  @Value("${application.security.jwt.secret-key}")
  private String secretKey;

  @Getter
  @Value("${application.security.access-token.expiration:3600000}")
  private long accessTokenExpiration; // in milliseconds - default 1 hour

  @Getter
  @Value("${application.security.refresh-token.expiration:604800000}")
  private long refreshTokenExpiration; // in milliseconds - default 7 days

  public String generateToken(User user, long expirationMs) {
    Map<String, Object> claims = new HashMap<>();
    claims.put(CLAIMS_USER_ID, user.getId().toString());
    claims.put(CLAIMS_ROLE, user.getRole().name());

    return buildToken(claims, user.getEmail(), expirationMs);
  }

  /** Builds the JWT token using standard claims and the provided user email. */
  private String buildToken(Map<String, Object> claims, String subject, long expirationMs) {
    long now = System.currentTimeMillis();
    return Jwts.builder()
        .setClaims(claims)
        .setSubject(subject)
        .setIssuedAt(new Date(now))
        .setExpiration(new Date(now + expirationMs))
        .signWith(getSignInKey(), SignatureAlgorithm.HS256)
        .compact();
  }

  public String generateAccessToken(User user) {
    return generateToken(user, accessTokenExpiration);
  }

  public String generateRefreshToken(User user) {
    return generateToken(user, refreshTokenExpiration);
  }

  // --- Token Validation and Extraction Methods ---

  public boolean isTokenValid(String token) {
    try {
      return !isTokenExpired(token);
    } catch (Exception e) {
      // Handle exceptions like SignatureException, MalformedJwtException, etc.
      return false;
    }
  }

  private boolean isTokenExpired(String token) {
    return extractExpiration(token).before(new Date());
  }

  /** Extracts the expiration date from the JWT claims. */
  private Date extractExpiration(String token) {
    return extractClaim(token, Claims::getExpiration);
  }

  public Claims extractAllClaims(String token) {
    return Jwts.parser().setSigningKey(getSignInKey()).build().parseClaimsJws(token).getBody();
  }

  public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }

  public String extractUsername(String token) {
    return extractClaim(token, Claims::getSubject);
  }

  public UUID extractUserId(String token) {
    // We stored the userId as a string in the claims
    String userIdStr = extractClaim(token, claims -> claims.get(CLAIMS_USER_ID, String.class));
    return UUID.fromString(userIdStr);
  }

  public UserRole extractUserRole(String token) {
    // We stored the role as a string in the claims
    String roleStr = extractClaim(token, claims -> claims.get(CLAIMS_ROLE, String.class));
    return UserRole.valueOf(roleStr);
  }

  private Key getSignInKey() {
    byte[] keyBytes = Decoders.BASE64.decode(secretKey);
    return Keys.hmacShaKeyFor(keyBytes);
  }
}
