package com.mylearn.auth.repository;

import com.mylearn.auth.entity.User;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Spring Data JPA Repository for the User entity. Provides standard CRUD and querying capabilities.
 */
@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

  /**
   * Finds a User by their unique email address.
   *
   * @param email the user's email.
   * @return an Optional containing the User if found, or empty otherwise.
   */
  Optional<User> findByEmail(String email);

  /**
   * Checks if a user exists with the given email address.
   *
   * @param email the email to check.
   * @return true if a user exists, false otherwise.
   */
  boolean existsByEmail(String email);
}
