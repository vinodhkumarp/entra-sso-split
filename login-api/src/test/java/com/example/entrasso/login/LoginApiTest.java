package com.example.entrasso.login;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.entrasso.login.api.LoginApiDelegateService;
import com.example.entrasso.login.generated.api.AuthApiController;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.JwtRequestPostProcessor;
import org.springframework.test.web.servlet.MockMvc;

/** Exercises the real filter chain from the SSO library against the login endpoint. */
@SpringBootTest(
    properties = {
      "spring.security.oauth2.resourceserver.jwt.issuer-uri=https://issuer.example.test",
      "spring.security.oauth2.resourceserver.jwt.audiences=test-api"
    })
@AutoConfigureMockMvc
@Import(LoginApiTest.DecoderConfiguration.class)
class LoginApiTest {

  @Autowired private MockMvc mockMvc;

  @Autowired private AuthApiController authApiController;

  /** Verifies the generated controller is wired to the handwritten login delegate. */
  @Test
  void wiresGeneratedControllerToLoginDelegate() {
    assertThat(AopUtils.getTargetClass(authApiController.getDelegate()))
        .isEqualTo(LoginApiDelegateService.class);
  }

  /** Verifies a bearer token is mandatory. */
  @Test
  void rejectsMissingToken() throws Exception {
    mockMvc
        .perform(post("/api/login").header("X-Correlation-Id", "missing-token-123"))
        .andExpect(status().isUnauthorized())
        .andExpect(header().string("X-Correlation-Id", "missing-token-123"))
        .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("Bearer")))
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
        .andExpect(jsonPath("$.code").value("AUTHENTICATION_REQUIRED"));
  }

  /** Verifies the delegated API scope is mandatory even when an app role is present. */
  @Test
  void rejectsTokenWithoutRequiredScope() throws Exception {
    mockMvc
        .perform(
            post("/api/login")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_APP_USER"))))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.code").value("ACCESS_DENIED"));
  }

  /** Verifies an ordinary user is logged in with only the dashboard functionality. */
  @Test
  void returnsUserRoleAndFunctionality() throws Exception {
    mockMvc
        .perform(post("/api/login").with(token("user-1", "APP_USER")))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.subjectId").value("user-1"))
        .andExpect(jsonPath("$.username").value("user-1@example.test"))
        .andExpect(jsonPath("$.tenantId").value("tenant-1"))
        .andExpect(jsonPath("$.roles[0]").value("APP_USER"))
        .andExpect(jsonPath("$.functionalities", containsInAnyOrder("DASHBOARD_VIEW")));
  }

  /** Verifies a manager receives dashboard and reports functionality. */
  @Test
  void returnsManagerRoleAndFunctionality() throws Exception {
    mockMvc
        .perform(post("/api/login").with(token("manager-1", "APP_MANAGER")))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.roles[0]").value("APP_MANAGER"))
        .andExpect(
            jsonPath("$.functionalities", containsInAnyOrder("DASHBOARD_VIEW", "REPORTS_VIEW")));
  }

  /** Verifies an administrator receives every functionality. */
  @Test
  void returnsAdministratorRoleAndFunctionality() throws Exception {
    mockMvc
        .perform(post("/api/login").with(token("admin-1", "APP_ADMIN")))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath(
                "$.functionalities",
                containsInAnyOrder("DASHBOARD_VIEW", "REPORTS_VIEW", "ADMIN_USERS_VIEW")));
  }

  /** Verifies a valid token with no app roles still logs in, with empty roles. */
  @Test
  void returnsEmptyRolesWhenTokenHasNone() throws Exception {
    mockMvc
        .perform(post("/api/login").with(token("norole-1")))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.roles").isEmpty())
        .andExpect(jsonPath("$.functionalities").isEmpty());
  }

  /** Verifies business endpoints do not exist on the login component. */
  @Test
  void doesNotExposeBusinessEndpoints() throws Exception {
    mockMvc
        .perform(get("/api/dashboard").with(token("admin-1", "APP_ADMIN")))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("RESOURCE_NOT_FOUND"));
  }

  /** Creates a validated-token stand-in with the scope, claims and role authorities. */
  private static JwtRequestPostProcessor token(String oid, String... roles) {
    var authorities =
        new java.util.ArrayList<GrantedAuthority>(
            List.of(new SimpleGrantedAuthority("SCOPE_access_as_user")));
    for (String role : roles) {
      authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
    }
    return jwt()
        .jwt(
            token ->
                token
                    .claim("oid", oid)
                    .claim("preferred_username", oid + "@example.test")
                    .claim("name", "Example " + oid)
                    .claim("tid", "tenant-1")
                    .claim("roles", List.of(roles))
                    .expiresAt(Instant.now().plusSeconds(300)))
        .authorities(authorities);
  }

  /** Supplies a local decoder so tests never call Microsoft Entra endpoints. */
  @TestConfiguration(proxyBeanMethods = false)
  static class DecoderConfiguration {

    /** Creates a placeholder decoder; SecurityMockMvc injects authenticated test JWTs. */
    @Bean
    JwtDecoder jwtDecoder() {
      return token -> {
        throw new BadJwtException("decoder implementation detail must not reach the client");
      };
    }
  }
}
