/*
 * Copyright 2024-2026 Firefly Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.fireflyframework.security.authz;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end test of the embedded authorization server: OIDC discovery, the published JWKS, and a
 * real {@code client_credentials} token exchange that yields a verifiable JWT.
 */
@SpringBootTest(classes = AuthorizationServerIntegrationTest.TestApp.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "spring.main.banner-mode=off")
class AuthorizationServerIntegrationTest {

    @Autowired
    TestRestTemplate restTemplate;

    @Test
    void publishesOidcDiscoveryDocument() {
        ResponseEntity<String> response = restTemplate.getForEntity("/.well-known/openid-configuration", String.class);
        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).contains("\"issuer\"").contains("\"jwks_uri\"").contains("\"token_endpoint\"");
    }

    @Test
    void publishesJwks() {
        ResponseEntity<String> response = restTemplate.getForEntity("/oauth2/jwks", String.class);
        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).contains("\"keys\"").contains("\"kty\":\"RSA\"");
    }

    @Test
    void issuesClientCredentialsTokenAsJwt() {
        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth("firefly-demo", "firefly-secret");
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("scope", "read");

        ResponseEntity<String> response = restTemplate.postForEntity(
                "/oauth2/token", new HttpEntity<>(form, headers), String.class);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).contains("access_token").contains("\"token_type\":\"Bearer\"");
        // access_token is a signed JWT: three dot-separated base64url segments
        String body = response.getBody();
        int idx = body.indexOf("\"access_token\":\"") + "\"access_token\":\"".length();
        String token = body.substring(idx, body.indexOf('"', idx));
        assertThat(token.chars().filter(c -> c == '.').count()).isEqualTo(2);
    }

    @SpringBootApplication
    static class TestApp {
    }
}
