package com.example.entrasso.sso.security;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.validation.Validation;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/** Tests configuration-driven endpoint role authorization and its startup constraints. */
class RoleAuthorizationServiceTest {

  /** Verifies each endpoint key uses only its own configured role set. */
  @Test
  void evaluatesConfiguredRolesForEachEndpoint() {
    RoleAuthorizationService service = new RoleAuthorizationService(properties());
    var user = authenticatedAs("APP_USER");
    var manager = authenticatedAs("APP_MANAGER");
    var administrator = authenticatedAs("APP_ADMIN");

    assertThat(service.canAccess(user, "dashboard")).isTrue();
    assertThat(service.canAccess(user, "reports")).isFalse();
    assertThat(service.canAccess(user, "admin-users")).isFalse();

    assertThat(service.canAccess(manager, "dashboard")).isTrue();
    assertThat(service.canAccess(manager, "reports")).isTrue();
    assertThat(service.canAccess(manager, "admin-users")).isFalse();

    assertThat(service.canAccess(administrator, "dashboard")).isTrue();
    assertThat(service.canAccess(administrator, "reports")).isTrue();
    assertThat(service.canAccess(administrator, "admin-users")).isTrue();
  }

  /** Verifies missing, unauthenticated, and unrelated principals are denied rather than failing. */
  @Test
  void deniesPrincipalsWithoutAConfiguredRole() {
    RoleAuthorizationService service = new RoleAuthorizationService(properties());
    var unauthenticated = UsernamePasswordAuthenticationToken.unauthenticated("user", "password");

    assertThat(service.canAccess(null, "dashboard")).isFalse();
    assertThat(service.canAccess(unauthenticated, "dashboard")).isFalse();
    assertThat(service.canAccess(authenticatedAs("UNRELATED_ROLE"), "dashboard")).isFalse();
  }

  /** Verifies an endpoint key with no configuration fails closed, even for an administrator. */
  @Test
  void deniesUnconfiguredEndpointKeys() {
    RoleAuthorizationService service = new RoleAuthorizationService(properties());

    assertThat(service.canAccess(authenticatedAs("APP_ADMIN"), "not-configured")).isFalse();
  }

  /** Verifies authorization follows an external role value without changing application code. */
  @Test
  void honorsAChangedRoleValueFromConfiguration() {
    var configured =
        new EntraSecurityProperties(
            "access_as_user",
            List.of("http://localhost:5173"),
            Map.of("dashboard", Set.of("ORG_DASHBOARD_READER")),
            Map.of());
    RoleAuthorizationService service = new RoleAuthorizationService(configured);

    assertThat(service.canAccess(authenticatedAs("ORG_DASHBOARD_READER"), "dashboard")).isTrue();
    assertThat(service.canAccess(authenticatedAs("APP_USER"), "dashboard")).isFalse();
  }

  /** Verifies an endpoint declared with an empty role list is rejected by validation. */
  @Test
  void rejectsEmptyEndpointRoleList() {
    var invalid =
        new EntraSecurityProperties(
            "access_as_user",
            List.of("http://localhost:5173"),
            Map.of("dashboard", Set.of()),
            Map.of());

    try (var validatorFactory = Validation.buildDefaultValidatorFactory()) {
      assertThat(validatorFactory.getValidator().validate(invalid)).isNotEmpty();
    }
  }

  /** Verifies an API with no protected business endpoints (the login API) is valid. */
  @Test
  void acceptsMissingEndpointRoles() {
    var valid =
        new EntraSecurityProperties("access_as_user", List.of("http://localhost:5173"), null, null);

    try (var validatorFactory = Validation.buildDefaultValidatorFactory()) {
      assertThat(validatorFactory.getValidator().validate(valid)).isEmpty();
    }
  }

  /** Creates an authenticated principal with the same authority prefix used by JWT conversion. */
  private static UsernamePasswordAuthenticationToken authenticatedAs(String role) {
    return UsernamePasswordAuthenticationToken.authenticated(
        "user", "not-used", List.of(new SimpleGrantedAuthority("ROLE_" + role)));
  }

  /** Creates representative immutable endpoint-role configuration for the unit tests. */
  private static EntraSecurityProperties properties() {
    return new EntraSecurityProperties(
        "access_as_user",
        List.of("http://localhost:5173"),
        Map.of(
            "dashboard", Set.of("APP_USER", "APP_MANAGER", "APP_ADMIN"),
            "reports", Set.of("APP_MANAGER", "APP_ADMIN"),
            "admin-users", Set.of("APP_ADMIN")),
        Map.of());
  }
}
