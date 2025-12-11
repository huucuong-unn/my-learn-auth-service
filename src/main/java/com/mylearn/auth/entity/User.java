package com.mylearn.auth.entity;

import com.mylearn.common.enums.UserRole;
import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

@Entity
@Table(name = "auth_users")
@Getter
@Setter
public class User {

  /**
   * Unique identifier for the user. Uses UUID for distributed uniqueness, ideal for microservices.
   */
  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  /** User's unique email address, used for login. Must be unique across the entire table. */
  @Column(nullable = false, unique = true)
  private String email;

  /**
   * Hashed password using BCrypt or similar secure algorithm. Must never be stored in plain text.
   */
  @Column(nullable = false)
  private String passwordHash;

  /** User role (e.g., LEARNER, INSTRUCTOR, ADMIN). Stored as a String in the database. */
  @Enumerated(EnumType.STRING)
  @Column(nullable = false)
  private UserRole role;

  /**
   * A temporary field to store the refresh token. In a production environment, this token would
   * typically be stored in a secure Redis/Cache store. For now, storing it here for simplicity.
   */
  // TODO: Migrate to Redis or secure store in future iterations.
  @Column(length = 512)
  private String refreshToken;

  @CreationTimestamp
  @Column(nullable = false, updatable = false)
  private Instant createdAt;

  @UpdateTimestamp
  @Column(nullable = false)
  private Instant updatedAt;

  public User() {
    this.role = UserRole.LEARNER; // Default role upon registration
  }
}
