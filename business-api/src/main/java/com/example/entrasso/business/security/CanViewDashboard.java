package com.example.entrasso.business.security;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.security.access.prepost.PreAuthorize;

/** Authorizes a method using the roles configured under {@code app.security.endpoint-roles.dashboard}. */
@Documented
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("@roleAuthorization.canAccess(authentication, 'dashboard')")
public @interface CanViewDashboard {}
