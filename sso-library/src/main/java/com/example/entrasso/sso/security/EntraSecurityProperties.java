package com.example.entrasso.sso.security;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Validated scope, browser-origin, endpoint-role, and role-to-functionality settings.
 *
 * <p>The library knows nothing about specific business endpoints. Each consuming API declares its
 * own endpoint keys under {@code app.security.endpoint-roles} and checks them with {@link
 * RoleAuthorizationService#canAccess}. An endpoint key that is not configured is always denied.
 *
 * @param requiredScope delegated Entra scope required at the HTTP boundary
 * @param allowedOrigins exact browser origins allowed by CORS
 * @param endpointRoles application roles allowed per endpoint key (may be empty, e.g. login API)
 * @param roleFunctionalities UI functionality names contributed by each Entra app role
 */
@Validated
@ConfigurationProperties("app.security")
public record EntraSecurityProperties(
    @NotBlank String requiredScope,
    @NotEmpty List<@NotBlank String> allowedOrigins,
    Map<@NotBlank String, @NotEmpty Set<@NotBlank String>> endpointRoles,
    Map<String, List<String>> roleFunctionalities) {

  /** Creates immutable defensive copies so configuration cannot change after startup. */
  public EntraSecurityProperties {
    allowedOrigins = allowedOrigins == null ? List.of() : List.copyOf(allowedOrigins);
    endpointRoles =
        endpointRoles == null
            ? Map.of()
            : endpointRoles.entrySet().stream()
                .collect(
                    Collectors.toUnmodifiableMap(
                        Map.Entry::getKey, entry -> Set.copyOf(entry.getValue())));
    roleFunctionalities =
        roleFunctionalities == null
            ? Map.of()
            : roleFunctionalities.entrySet().stream()
                .collect(
                    Collectors.toUnmodifiableMap(
                        Map.Entry::getKey, entry -> List.copyOf(entry.getValue())));
  }
}
