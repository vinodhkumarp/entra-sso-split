package com.example.entrasso.sso.security;

import java.util.List;
import java.util.Optional;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

/** Reads the current caller's identity and roles from the validated JWT principal. */
@Component
public class CurrentUserService {

  /** Creates the stateless helper. */
  public CurrentUserService() {}

  /**
   * Returns the caller described by the bearer token Spring Security already validated.
   *
   * <p>This neither authenticates the user nor issues a token.
   *
   * @throws AuthenticationCredentialsNotFoundException if no JWT principal or expiry is available
   */
  public AuthenticatedUser current() {
    Jwt jwt = currentJwt();
    List<String> roles =
        Optional.ofNullable(jwt.getClaimAsStringList("roles")).orElseGet(List::of).stream()
            .sorted()
            .toList();
    String username =
        firstPresent(
            jwt.getClaimAsString("preferred_username"),
            jwt.getClaimAsString("upn"),
            jwt.getSubject());
    String subjectId = firstPresent(jwt.getClaimAsString("oid"), jwt.getSubject());
    String displayName = firstPresent(jwt.getClaimAsString("name"), username);
    String tenantId = firstPresent(jwt.getClaimAsString("tid"));
    var expiresAt =
        Optional.ofNullable(jwt.getExpiresAt())
            .orElseThrow(
                () ->
                    new AuthenticationCredentialsNotFoundException(
                        "The validated access token does not contain an expiration time"));
    return new AuthenticatedUser(subjectId, username, displayName, tenantId, roles, expiresAt);
  }

  /** Returns the validated JWT principal stored by Spring Security for the current request. */
  private static Jwt currentJwt() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null || !(authentication.getPrincipal() instanceof Jwt jwt)) {
      throw new AuthenticationCredentialsNotFoundException(
          "A validated JWT principal is required for this operation");
    }
    return jwt;
  }

  /** Returns the first non-blank claim value, or an empty string when none is available. */
  private static String firstPresent(String... candidates) {
    for (String candidate : candidates) {
      if (candidate != null && !candidate.isBlank()) {
        return candidate;
      }
    }
    return "";
  }
}
