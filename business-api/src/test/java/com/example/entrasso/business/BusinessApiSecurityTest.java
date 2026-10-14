package com.example.entrasso.business;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.entrasso.business.api.AdminUsersApiDelegateService;
import com.example.entrasso.business.api.BusinessApiDelegateService;
import com.example.entrasso.business.generated.api.AdminUsersApiController;
import com.example.entrasso.business.generated.api.BusinessApiController;
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

/** Exercises the real filter chain and method authorization across every business endpoint. */
@SpringBootTest(
    properties = {
      "spring.security.oauth2.resourceserver.jwt.issuer-uri=https://issuer.example.test",
      "spring.security.oauth2.resourceserver.jwt.audiences=test-api"
    })
@AutoConfigureMockMvc
@Import(BusinessApiSecurityTest.DecoderConfiguration.class)
class BusinessApiSecurityTest {

  @Autowired private MockMvc mockMvc;

  @Autowired private AdminUsersApiController adminUsersApiController;

  @Autowired private BusinessApiController businessApiController;

  /** Verifies generated controllers are active and wired to the handwritten delegates. */
  @Test
  void wiresGeneratedControllersToApplicationDelegates() {
    assertThat(AopUtils.getTargetClass(adminUsersApiController.getDelegate()))
        .isEqualTo(AdminUsersApiDelegateService.class);
    assertThat(AopUtils.getTargetClass(businessApiController.getDelegate()))
        .isEqualTo(BusinessApiDelegateService.class);
  }

  /** Verifies a bearer token is mandatory for all protected endpoints. */
  @Test
  void rejectsMissingToken() throws Exception {
    mockMvc
        .perform(get("/api/dashboard").header("X-Correlation-Id", "missing-token-123"))
        .andExpect(status().isUnauthorized())
        .andExpect(header().string("X-Correlation-Id", "missing-token-123"))
        .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("Bearer")))
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
        .andExpect(jsonPath("$.code").value("AUTHENTICATION_REQUIRED"));
    mockMvc.perform(get("/api/reports")).andExpect(status().isUnauthorized());
    mockMvc.perform(get("/api/admin/users")).andExpect(status().isUnauthorized());
  }

  /** Verifies the delegated API scope is mandatory even when an app role is present. */
  @Test
  void rejectsTokenWithoutRequiredScope() throws Exception {
    mockMvc
        .perform(
            get("/api/dashboard")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_APP_ADMIN"))))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.code").value("ACCESS_DENIED"));
  }

  /** Verifies a valid token with no application role is denied on every endpoint. */
  @Test
  void deniesTokenWithoutAnyApplicationRole() throws Exception {
    var noRole = token();
    mockMvc.perform(get("/api/dashboard").with(noRole)).andExpect(status().isForbidden());
    mockMvc.perform(get("/api/reports").with(noRole)).andExpect(status().isForbidden());
    mockMvc.perform(get("/api/admin/users").with(noRole)).andExpect(status().isForbidden());
  }

  /** Verifies an ordinary application user can load only the dashboard. */
  @Test
  void appliesApplicationUserRole() throws Exception {
    var user = token("APP_USER");
    mockMvc.perform(get("/api/dashboard").with(user)).andExpect(status().isOk());
    mockMvc
        .perform(get("/api/reports").with(user))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.code").value("ACCESS_DENIED"));
    mockMvc.perform(get("/api/admin/users").with(user)).andExpect(status().isForbidden());
  }

  /** Verifies a manager can load dashboard and report data but not administrator data. */
  @Test
  void appliesManagerRole() throws Exception {
    var manager = token("APP_MANAGER");
    mockMvc.perform(get("/api/dashboard").with(manager)).andExpect(status().isOk());
    mockMvc
        .perform(get("/api/reports").with(manager))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.reports[0]").value("monthly-summary.csv"));
    mockMvc.perform(get("/api/admin/users").with(manager)).andExpect(status().isForbidden());
  }

  /** Verifies an application administrator can call every endpoint. */
  @Test
  void allowsAdministratorToUseEveryEndpoint() throws Exception {
    var administrator = token("APP_ADMIN");
    mockMvc.perform(get("/api/dashboard").with(administrator)).andExpect(status().isOk());
    mockMvc.perform(get("/api/reports").with(administrator)).andExpect(status().isOk());
    mockMvc
        .perform(get("/api/admin/users").with(administrator))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].id").value("demo-user-1"));
  }

  /** Verifies the login endpoint does not exist on the business component. */
  @Test
  void doesNotExposeLogin() throws Exception {
    mockMvc
        .perform(post("/api/login").with(token("APP_ADMIN")))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("RESOURCE_NOT_FOUND"));
  }

  /** Creates a validated-token stand-in carrying the scope and the given role authorities. */
  private static JwtRequestPostProcessor token(String... roles) {
    var authorities = new java.util.ArrayList<GrantedAuthority>();
    authorities.add(new SimpleGrantedAuthority("SCOPE_access_as_user"));
    for (String role : roles) {
      authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
    }
    return jwt().authorities(authorities);
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
