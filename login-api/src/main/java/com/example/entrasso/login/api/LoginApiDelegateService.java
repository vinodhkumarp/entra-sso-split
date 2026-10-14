package com.example.entrasso.login.api;

import com.example.entrasso.login.generated.api.AuthApiDelegate;
import com.example.entrasso.login.generated.model.LoginResponse;
import com.example.entrasso.sso.security.AuthenticatedUser;
import com.example.entrasso.sso.security.CurrentUserService;
import com.example.entrasso.sso.security.RoleFunctionalityService;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import org.springframework.stereotype.Service;

/** Supplies login behavior to the generated {@code /api/login} controller. */
@Service
public class LoginApiDelegateService implements AuthApiDelegate {

  private final CurrentUserService currentUserService;
  private final RoleFunctionalityService functionalityService;

  /** Creates the delegate from the shared SSO library services. */
  public LoginApiDelegateService(
      CurrentUserService currentUserService, RoleFunctionalityService functionalityService) {
    this.currentUserService = currentUserService;
    this.functionalityService = functionalityService;
  }

  /**
   * Returns identity, roles and UI functionality derived only from the already-validated token.
   *
   * <p>The security filter chain from the SSO library has verified the token and the required
   * scope before this method runs. No token is issued here; the SPA gets it from Microsoft Entra.
   */
  @Override
  public LoginResponse login() {
    AuthenticatedUser user = currentUserService.current();
    List<String> functionalities = functionalityService.resolve(user.roles()).stream().toList();
    return new LoginResponse(
        user.subjectId(),
        user.username(),
        user.displayName(),
        user.tenantId(),
        user.roles(),
        functionalities,
        OffsetDateTime.ofInstant(user.tokenExpiresAt(), ZoneOffset.UTC));
  }
}
