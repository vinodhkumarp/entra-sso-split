# Entra SSO – split into a library and two APIs

The single Spring Boot API in `entra-sso-react-spring-reference` is split into three Maven modules.
The original project is untouched; this folder is independent.

```
entra-sso-split/
├── sso-library/   Reusable SSO jar (no main class)
├── login-api/     Component 1 – only POST /api/login          (port 8081)
└── business-api/  Component 2 – dashboard/reports/admin users (port 8082)
```

## What lives where

| Module | Contains |
|---|---|
| `sso-library` | JWT resource-server filter chain (issuer/audience/expiry via Spring, required scope check), CORS, `roles`/`scp` → authorities converter, `RoleAuthorizationService` (bean `roleAuthorization`), `RoleFunctionalityService`, `CurrentUserService` (identity + roles from the validated token), RFC 9457 problem+json error handling, correlation-ID filter, JSON logging (`logback-spring.xml`) |
| `login-api` | `POST /api/login` – validates the token through the library and returns `subjectId`, `username`, `displayName`, `tenantId`, `roles`, `functionalities`, `tokenExpiresAt`. Replaces the old `GET /api/me`. |
| `business-api` | `GET /api/dashboard`, `GET /api/reports`, `GET /api/admin/users` – each guarded by a `@CanView*` annotation that checks the caller's roles against configuration. |

## How the library is consumed

1. Add the dependency (`com.example:sso-library`).
2. Put `@EnableEntraSso` next to `@SpringBootApplication`.
3. Configure `app.security.*` in `application.yml`:
   - `required-scope`, `allowed-origins` – both APIs
   - `role-functionalities` – used by the login API
   - `endpoint-roles` – a map of endpoint key → allowed Entra app roles (business API)
4. Protect an endpoint with a role check. In `business-api` this is a small annotation:

   ```java
   @PreAuthorize("@roleAuthorization.canAccess(authentication, 'reports')")
   public @interface CanViewReports {}
   ```

   `canAccess` fails closed: an endpoint key with no configured roles denies everyone.

The library is deliberately business-agnostic. The old fixed `dashboard/reports/adminUsers` properties
became the generic `endpoint-roles` map, so a new endpoint needs only a new key and an annotation – no
library change.

## Build, test, run

Requires JDK 25 (same as the reference project) and Maven. The Maven wrapper is included.

```bash
./mvnw clean verify                      # builds the library, then both APIs, runs all tests

export ENTRA_TENANT_ID=<tenant-guid>
export ENTRA_API_CLIENT_ID=<api-app-client-id>
./mvnw -pl login-api    spring-boot:run  # http://localhost:8081
./mvnw -pl business-api spring-boot:run  # http://localhost:8082
```

Both APIs validate tokens for the **same Entra API app registration** (same audience, same
`access_as_user` scope, same app roles), so one SPA token works against both. The SPA calls
`POST :8081/api/login` after sign-in to learn roles/functionalities, then calls the business API
with the same bearer token.

```bash
curl -X POST http://localhost:8081/api/login     -H "Authorization: Bearer $TOKEN"
curl         http://localhost:8082/api/reports   -H "Authorization: Bearer $TOKEN"
```

## Behavior notes

- `/api/login` does not issue a token – Entra does, as before. It validates and reports the caller's roles.
- A valid token with no app roles still gets a `200` from `/api/login` (empty `roles`), matching the old
  `/api/me`; the business API then returns `403` for every endpoint.
- Each API returns `404` problem+json for the other component's paths.
- The reference project's extra quality gates (Checkstyle, SpotBugs, Spotless, JaCoCo threshold, OWASP,
  SBOM, enforcer) were not carried over, to keep this quick. They can be copied from the reference
  `backend/pom.xml` into the parent `pom.xml` if you want them.
