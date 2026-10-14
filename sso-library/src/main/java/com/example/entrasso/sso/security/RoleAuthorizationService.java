package com.example.entrasso.sso.security;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

/**
 * Evaluates endpoint access against the application-role allow-lists loaded from configuration.
 *
 * <p>Registered under the bean name {@code roleAuthorization} so consuming APIs can use it from
 * {@code @PreAuthorize("@roleAuthorization.canAccess(authentication, 'reports')")}.
 */
@Component("roleAuthorization")
public class RoleAuthorizationService {

  private static final String ROLE_AUTHORITY_PREFIX = "ROLE_";

  private final EntraSecurityProperties properties;

  /** Creates the authorization service from validated, immutable security configuration. */
  public RoleAuthorizationService(EntraSecurityProperties properties) {
    this.properties = properties;
  }

  /**
   * Returns whether the principal holds any role configured for the endpoint key.
   *
   * <p>Missing, unauthenticated, and unconfigured cases fail closed (deny).
   */
  public boolean canAccess(Authentication authentication, String endpointKey) {
    Set<String> configuredRoles = properties.endpointRoles().getOrDefault(endpointKey, Set.of());
    return hasAnyConfiguredRole(authentication, configuredRoles);
  }

  /**
   * Compares configured Entra role values with Spring authorities produced by the JWT converter.
   *
   * <p>For example, the configured value {@code APP_ADMIN} matches the Spring authority {@code
   * ROLE_APP_ADMIN}.
   */
  private static boolean hasAnyConfiguredRole(
      Authentication authentication, Collection<String> configuredRoles) {
    if (authentication == null || !authentication.isAuthenticated()) {
      return false;
    }

    Set<String> grantedAuthorities =
        authentication.getAuthorities().stream()
            .map(authority -> authority.getAuthority())
            .collect(Collectors.toUnmodifiableSet());

    return configuredRoles.stream()
        .map(role -> ROLE_AUTHORITY_PREFIX + role)
        .anyMatch(grantedAuthorities::contains);
  }
}
