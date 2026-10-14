package com.example.entrasso.sso.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/** Tests extraction of identity and roles from the validated JWT principal. */
class CurrentUserServiceTest {

  private final CurrentUserService service = new CurrentUserService();

  /** Clears the thread-local security context so tests stay independent. */
  @AfterEach
  void clearContext() {
    SecurityContextHolder.clearContext();
  }

  /** Verifies all identity claims are mapped and roles are sorted. */
  @Test
  void mapsClaimsAndSortsRoles() {
    Instant expiry = Instant.now().plusSeconds(300);
    authenticate(
        Jwt.withTokenValue("token")
            .header("alg", "none")
            .subject("sub-1")
            .claim("oid", "oid-1")
            .claim("preferred_username", "user@example.test")
            .claim("name", "Example User")
            .claim("tid", "tenant-1")
            .claim("roles", List.of("APP_MANAGER", "APP_ADMIN"))
            .expiresAt(expiry)
            .build());

    AuthenticatedUser user = service.current();

    assertThat(user.subjectId()).isEqualTo("oid-1");
    assertThat(user.username()).isEqualTo("user@example.test");
    assertThat(user.displayName()).isEqualTo("Example User");
    assertThat(user.tenantId()).isEqualTo("tenant-1");
    assertThat(user.roles()).containsExactly("APP_ADMIN", "APP_MANAGER");
    assertThat(user.tokenExpiresAt()).isEqualTo(expiry);
  }

  /** Verifies fallbacks when optional claims are absent. */
  @Test
  void fallsBackToSubjectAndEmptyRoles() {
    authenticate(
        Jwt.withTokenValue("token")
            .header("alg", "none")
            .subject("sub-1")
            .expiresAt(Instant.now().plusSeconds(300))
            .build());

    AuthenticatedUser user = service.current();

    assertThat(user.subjectId()).isEqualTo("sub-1");
    assertThat(user.username()).isEqualTo("sub-1");
    assertThat(user.displayName()).isEqualTo("sub-1");
    assertThat(user.tenantId()).isEmpty();
    assertThat(user.roles()).isEmpty();
  }

  /** Verifies a token without an expiry is rejected as missing credentials. */
  @Test
  void rejectsTokenWithoutExpiry() {
    authenticate(Jwt.withTokenValue("token").header("alg", "none").subject("sub-1").build());

    assertThatThrownBy(service::current)
        .isInstanceOf(AuthenticationCredentialsNotFoundException.class);
  }

  /** Verifies a missing authentication is rejected as missing credentials. */
  @Test
  void rejectsMissingAuthentication() {
    assertThatThrownBy(service::current)
        .isInstanceOf(AuthenticationCredentialsNotFoundException.class);
  }

  /** Stores the supplied JWT as the current request's authenticated principal. */
  private static void authenticate(Jwt jwt) {
    SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt));
  }
}
