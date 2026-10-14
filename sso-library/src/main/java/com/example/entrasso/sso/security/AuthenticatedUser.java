package com.example.entrasso.sso.security;

import java.time.Instant;
import java.util.List;

/**
 * Identity facts taken from the already-validated access token.
 *
 * @param subjectId stable user object identifier ({@code oid}, falling back to {@code sub})
 * @param username preferred username, UPN, or subject fallback
 * @param displayName display name, or the username when no name claim exists
 * @param tenantId Microsoft Entra tenant identifier
 * @param roles sorted application roles from the {@code roles} claim
 * @param tokenExpiresAt expiry of the validated access token
 */
public record AuthenticatedUser(
    String subjectId,
    String username,
    String displayName,
    String tenantId,
    List<String> roles,
    Instant tokenExpiresAt) {}
