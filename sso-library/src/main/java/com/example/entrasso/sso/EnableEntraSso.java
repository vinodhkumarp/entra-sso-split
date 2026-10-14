package com.example.entrasso.sso;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.context.annotation.Import;

/**
 * Switches on the shared Entra SSO behavior for a Spring Boot application.
 *
 * <p>Place this next to {@code @SpringBootApplication}. It registers the JWT resource-server filter
 * chain, role authorization, the problem+json error contract, correlation-ID logging, and the
 * current-user helper. It is an explicit opt-in (rather than auto-configuration) so the filter chain
 * is always defined before Spring Boot's default security chain and can never be silently skipped.
 */
@Documented
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Import(EntraSsoConfiguration.class)
public @interface EnableEntraSso {}
