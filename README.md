# Firefly Framework - Security Authorization Server

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-21%2B-orange.svg)](https://openjdk.org)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.x-green.svg)](https://spring.io/projects/spring-boot)
[![Spring Authorization Server](https://img.shields.io/badge/Spring%20Authorization%20Server-1.x-brightgreen.svg)](https://spring.io/projects/spring-authorization-server)

> Optional, **servlet-only** OAuth2/OIDC Authorization Server built on Spring Authorization Server. A single auto-configuration publishes OIDC discovery, a JWKS, and the standard token endpoints — with the published signing keys sourced from the framework's `KeyManagementPort` so the issuer and the reactive resource servers share one key lifecycle. Deployed as its own process, separate from the reactive resource servers it issues tokens for.

---

## Table of Contents

- [Overview](#overview)
- [Where it sits in the platform](#where-it-sits-in-the-platform)
- [What it provides](#what-it-provides)
- [Key types](#key-types)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Endpoints](#endpoints)
- [Deployment topology](#deployment-topology)
- [Testing](#testing)
- [License](#license)

## Overview

This module is the **issuer binding** of the Firefly hexagonal security platform. It packages Spring Authorization Server as a drop-in, runnable OAuth2/OIDC provider and wires its signing material to the same `KeyManagementPort` that the resource servers verify against — so the keys an application issues tokens with and the keys it validates them with come from a single source of truth.

Spring Authorization Server is built on the Servlet stack (Spring MVC + the servlet `SecurityFilterChain`), so this module is **servlet-only** by design and is deployed as a standalone process. The reactive resource servers (`fireflyframework-security-resource-server`, Spring WebFlux) run separately and only need this server's public JWKS to verify the JWTs it mints. Nothing about this module is pulled into a reactive application; the two stacks are kept apart deliberately.

The whole module is one `@AutoConfiguration` class, `AuthorizationServerConfiguration`. Every bean it contributes that is meant to be replaced is `@ConditionalOnMissingBean`, so a deployment overrides the registered-client store, the authorization-server settings, the JWK source, or the key port without forking the module. Out of the box it registers a demo `client_credentials` client so the server is runnable with zero additional configuration.

## Where it sits in the platform

The security platform is layered hexagonally; dependencies point inward, and providers attach as outboard adapters:

```
security-api  →  security-spi  →  security-core  →  security-authorization-server  →  adapters
 (ports +         (driven           (neutral          (this module:                      (Vault, KMS,
  domain)          ports)            engine +          Spring Authorization Server         internal-db
                                     dev key)          issuer wiring, servlet-only)        client store, …)
```

- **`security-api`** defines the domain — including `SigningKey`, the RSA key-pair record this server turns into JWKS entries.
- **`security-spi`** defines the driven port this module consumes: `KeyManagementPort` (`activeSigningKey()`, `verificationKeys()`, `jwkSetJson()`, `rotate()`).
- **`security-core`** supplies the framework-neutral default key adapter, `InMemoryKeyManagementAdapter`, used as the dev/default `KeyManagementPort`.
- **This module** binds the above into a concrete Spring Authorization Server deployment: it builds a Nimbus `JWKSource` from the port's `verificationKeys()` and wires the standard OAuth2/OIDC filter chains.
- **Adapters** (key management, client store) replace the in-process defaults by contributing their own `KeyManagementPort` or `RegisteredClientRepository` beans — e.g. a Vault/AWS-KMS key adapter and an internal-db client store for production.

This module depends only on `security-spi` and `security-core` (which transitively bring `security-api`), plus `spring-boot-starter-web` and `spring-security-oauth2-authorization-server`. It imports no vendor SDK.

## What it provides

`AuthorizationServerConfiguration` contributes:

- **The authorization-server filter chain.** `authorizationServerSecurityFilterChain` (`@Order(1)`) applies `OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http)`, enables OIDC (`oidc(Customizer.withDefaults())`), and redirects unauthenticated `text/html` requests to `/login`. This chain owns the OAuth2/OIDC protocol endpoints.
- **A default form-login chain.** `defaultSecurityFilterChain` (`@Order(2)`) requires authentication for any other request and enables form login, so the authorization/consent flows have a working login page.
- **A JWKS sourced from the framework key port.** `jwkSource(KeyManagementPort)` (`@ConditionalOnMissingBean`) collects `KeyManagementPort.verificationKeys()`, converts each `SigningKey` into a Nimbus `RSAKey` (public key, private key, and `kid`), and exposes them as an `ImmutableJWKSet<SecurityContext>`. This is what the published JWKS and the signer draw from — the same keys the resource servers verify against.
- **A JWT decoder** built from that JWK source via `OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)`, for the server's own introspection/validation needs.
- **Authorization-server settings.** A default `AuthorizationServerSettings` (`@ConditionalOnMissingBean`), overridable to customise issuer URL and endpoint paths.
- **A default `KeyManagementPort`.** `authorizationServerKeyManagementPort()` (`@ConditionalOnMissingBean`) returns an `InMemoryKeyManagementAdapter` so the server boots with a working dev key; production contributes a real key adapter and this default steps aside.
- **A demo `client_credentials` client.** `registeredClientRepository()` (`@ConditionalOnMissingBean`) registers a single `RegisteredClient` — client id `firefly-demo`, secret `{noop}firefly-secret`, `client_secret_basic` authentication, the `client_credentials` grant, and scope `read` — in an `InMemoryRegisteredClientRepository`. Production overrides this bean (e.g. with an internal-db-backed store).

The auto-configuration is registered via `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`.

## Key types

| Type | Role |
| --- | --- |
| `AuthorizationServerConfiguration` | `@AutoConfiguration` entry point; builds the two servlet `SecurityFilterChain`s, the `JWKSource`, the `JwtDecoder`, the `AuthorizationServerSettings`, the default `KeyManagementPort`, and the demo `RegisteredClientRepository`. |

Port consumed (from `security-spi`): `KeyManagementPort`. Domain type (from `security-api`): `SigningKey`. Default key adapter (from `security-core`): `InMemoryKeyManagementAdapter`. The protocol machinery (`OAuth2AuthorizationServerConfiguration`, `OAuth2AuthorizationServerConfigurer`, `RegisteredClient`, `InMemoryRegisteredClientRepository`, `AuthorizationServerSettings`, Nimbus `JWKSource`/`RSAKey`) comes from Spring Authorization Server and Nimbus JOSE.

## Requirements

- Java 21+
- Spring Boot 3.x, Spring Authorization Server 1.x
- A **servlet** web stack (Spring MVC) — this module is not compatible with a reactive-only application context
- A `KeyManagementPort` that can resolve RSA verification keys (the bundled `InMemoryKeyManagementAdapter` suffices for dev; production deployments contribute a Vault/AWS-KMS/Azure-Key-Vault adapter, shared with the resource servers)

## Installation

The version is managed by the Firefly parent/BOM, so you can usually omit it. This server is deployed as its own application, so depend on it directly:

```xml
<dependency>
    <groupId>org.fireflyframework</groupId>
    <artifactId>fireflyframework-security-authorization-server</artifactId>
</dependency>
```

If you are not inheriting the Firefly parent, pin the version explicitly:

```xml
<dependency>
    <groupId>org.fireflyframework</groupId>
    <artifactId>fireflyframework-security-authorization-server</artifactId>
    <version>26.06.01</version>
</dependency>
```

## Quick Start

With the module on the classpath of a servlet Spring Boot application, the authorization server is fully wired — OIDC discovery, JWKS, and the token endpoint are live with **zero code**:

```java
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthorizationServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuthorizationServerApplication.class, args);
    }
}
```

Request a token with the bundled demo client:

```bash
curl -u firefly-demo:firefly-secret \
  -d 'grant_type=client_credentials&scope=read' \
  http://localhost:8080/oauth2/token
```

The response carries a signed JWT (`access_token`, `"token_type":"Bearer"`) whose signature verifies against the published JWKS — the same keys a Firefly resource server validates with.

For production, override the client store and the key port by contributing your own beans (both are `@ConditionalOnMissingBean`):

```java
@Bean
RegisteredClientRepository registeredClientRepository() {
    RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("payments-service")
            .clientSecret("{bcrypt}$2a$...")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .scope("payments.read")
            .build();
    return new InMemoryRegisteredClientRepository(client);
}

@Bean
KeyManagementPort keyManagementPort() {
    return new VaultKeyManagementAdapter(/* ... */); // shared with resource servers
}
```

## Endpoints

Served on the standard Spring Authorization Server paths:

| Endpoint | Path | Purpose |
| --- | --- | --- |
| OIDC discovery | `/.well-known/openid-configuration` | Advertises `issuer`, `jwks_uri`, `token_endpoint`, etc. |
| JWKS | `/oauth2/jwks` | Public keys (`{"keys":[{"kty":"RSA",...}]}`) drawn from `KeyManagementPort.verificationKeys()`. |
| Token | `/oauth2/token` | Issues tokens for the registered grants (demo: `client_credentials`). |

## Deployment topology

```
                         ┌──────────────────────────────────────┐
                         │  Authorization Server (this module)   │
                         │  Servlet · Spring Authorization Server│
   KeyManagementPort ───►│  /oauth2/token  /oauth2/jwks  OIDC    │
   (shared key source)   └──────────────────┬───────────────────┘
                                             │  publishes JWKS / signs JWTs
                                             ▼
                         ┌──────────────────────────────────────┐
                         │  Resource Servers (separate process)  │
                         │  Reactive · Spring WebFlux            │
                         │  verify JWT signature against JWKS    │
                         └──────────────────────────────────────┘
```

The issuer and the resource servers are deployed as distinct processes on distinct stacks (servlet vs. reactive). They are coupled only through the `KeyManagementPort` key material and the published JWKS — never through a shared application context.

## Testing

The module ships a `@SpringBootTest(webEnvironment = RANDOM_PORT)` integration test, `AuthorizationServerIntegrationTest`, that boots a **real** authorization server with the real auto-configuration and exercises the OAuth2/OIDC surface over HTTP with `TestRestTemplate`:

- **OIDC discovery** — `GET /.well-known/openid-configuration` returns 2xx and a body containing `"issuer"`, `"jwks_uri"`, and `"token_endpoint"`.
- **JWKS** — `GET /oauth2/jwks` returns 2xx and a body containing `"keys"` and `"kty":"RSA"`, proving the published keys are sourced from the wired `KeyManagementPort`.
- **client_credentials token** — `POST /oauth2/token` with HTTP-Basic `firefly-demo:firefly-secret` and `grant_type=client_credentials&scope=read` returns 2xx with `access_token` and `"token_type":"Bearer"`, and the returned `access_token` is asserted to be a signed JWT (three dot-separated base64url segments).

This is a genuine end-to-end exercise of the issuer — discovery, key publication, and a real token exchange that yields a verifiable JWT — not a mocked unit test.

## License

Copyright 2024-2026 Firefly Software Foundation.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
