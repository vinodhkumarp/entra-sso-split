package com.example.entrasso.sso.logging;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** Tests the safe-input rules for correlation and trace headers. */
class CorrelationIdFilterTest {

  /** Verifies a well-formed caller ID is reused. */
  @Test
  void reusesSafeCorrelationId() {
    assertThat(CorrelationIdFilter.resolveCorrelationId("ui-request-123"))
        .isEqualTo("ui-request-123");
  }

  /** Verifies unsafe or missing IDs are replaced rather than echoed into logs. */
  @Test
  void replacesUnsafeCorrelationId() {
    assertThat(CorrelationIdFilter.resolveCorrelationId("bad id\nwith newline"))
        .isNotEqualTo("bad id\nwith newline")
        .hasSize(36);
    assertThat(CorrelationIdFilter.resolveCorrelationId(null)).hasSize(36);
  }

  /** Verifies only a valid, non-zero W3C traceparent is accepted. */
  @Test
  void acceptsOnlyValidTraceparent() {
    String valid = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    assertThat(CorrelationIdFilter.resolveTraceparent(valid)).isEqualTo(valid);
    assertThat(CorrelationIdFilter.resolveTraceparent("garbage")).isEmpty();
    assertThat(CorrelationIdFilter.resolveTraceparent(null)).isEmpty();
    assertThat(
            CorrelationIdFilter.resolveTraceparent(
                "00-00000000000000000000000000000000-00f067aa0ba902b7-01"))
        .isEmpty();
  }
}
