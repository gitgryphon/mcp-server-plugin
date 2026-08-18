/*
 *
 * The MIT License
 *
 * Copyright (c) 2026, contributors.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

package io.jenkins.plugins.mcp.server.auth;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class McpBearerTokenValidatorTest {

    @BeforeEach
    void resetCache() {
        McpBearerTokenValidator.resetCacheForTests();
    }

    @Test
    void returnsServerErrorWhenConfigIsIncomplete(JenkinsRule jenkins) {
        McpOAuthConfiguration cfg = new McpOAuthConfiguration();
        cfg.setIssuer("https://issuer.example");
        cfg.setJwksUri(null);

        TokenValidationResult result = McpBearerTokenValidator.validate(
                "dummy", cfg, "https://jenkins.example/mcp-server/mcp");

        assertThat(result.decision()).isEqualTo(TokenValidationResult.Decision.SERVER_ERROR);
    }

    @Test
    void returnsUnauthorizedForMalformedJwt(JenkinsRule jenkins) {
        McpOAuthConfiguration cfg = new McpOAuthConfiguration();
        cfg.setIssuer("https://issuer.example");
        cfg.setJwksUri("https://issuer.example/jwks");

        TokenValidationResult result = McpBearerTokenValidator.validate(
                "not-a-jwt", cfg, "https://jenkins.example/mcp-server/mcp");

        assertThat(result.decision()).isEqualTo(TokenValidationResult.Decision.UNAUTHORIZED);
        assertThat(result.error()).isEqualTo("invalid_token");
    }

    @Test
    void rejectsNonHttpsIssuerOutsideLocalTestMode(JenkinsRule jenkins) throws Exception {
        RSAKey rsaJwk = new RSAKeyGenerator(2048).keyID("kid-http-issuer").generate();
        String jwksJson = new JWKSet(rsaJwk.toPublicJWK()).toString();

        try (JwksServer jwksServer = JwksServer.start(jwksJson)) {
            String issuer = "http://issuer.example";
            String audience = "https://jenkins.example/mcp-server/mcp";

            McpOAuthConfiguration cfg = new McpOAuthConfiguration();
            cfg.setIssuer(issuer);
            cfg.setJwksUri(jwksServer.jwksUri());
            cfg.setRequiredScopes("mcp.read");

            String token = signToken(rsaJwk, issuer, audience, "mcp.read");
            TokenValidationResult result = McpBearerTokenValidator.validate(token, cfg, audience);

            assertThat(result.decision()).isEqualTo(TokenValidationResult.Decision.SERVER_ERROR);
            assertThat(result.errorDescription()).contains("issuer must use https://");
        }
    }

    @Test
    void allowsHttpIssuerForLocalTestMode(JenkinsRule jenkins) throws Exception {
        RSAKey rsaJwk = new RSAKeyGenerator(2048).keyID("kid-local-issuer").generate();
        String jwksJson = new JWKSet(rsaJwk.toPublicJWK()).toString();

        try (JwksServer jwksServer = JwksServer.start(jwksJson)) {
            String issuer = "http://localhost";
            String audience = "https://jenkins.example/mcp-server/mcp";

            McpOAuthConfiguration cfg = new McpOAuthConfiguration();
            cfg.setIssuer(issuer);
            cfg.setJwksUri(jwksServer.jwksUri());
            cfg.setRequiredScopes("mcp.read");

            String token = signToken(rsaJwk, issuer, audience, "mcp.read");
            TokenValidationResult result = McpBearerTokenValidator.validate(token, cfg, audience);

            assertThat(result.decision()).isEqualTo(TokenValidationResult.Decision.ALLOW);
        }
    }

    @Test
    void allowsValidSignedTokenWithRequiredScope(JenkinsRule jenkins) throws Exception {
        RSAKey rsaJwk = new RSAKeyGenerator(2048).keyID("kid-1").generate();
        String jwksJson = new JWKSet(rsaJwk.toPublicJWK()).toString();

        try (JwksServer jwksServer = JwksServer.start(jwksJson)) {
            String issuer = "https://issuer.example";
            String audience = "https://jenkins.example/mcp-server/mcp";

            McpOAuthConfiguration cfg = new McpOAuthConfiguration();
            cfg.setIssuer(issuer);
            cfg.setJwksUri(jwksServer.jwksUri());
            cfg.setRequiredScopes("mcp.read");

            String token = signToken(rsaJwk, issuer, audience, "mcp.read other");
            TokenValidationResult result = McpBearerTokenValidator.validate(token, cfg, audience);

            assertThat(result.decision()).isEqualTo(TokenValidationResult.Decision.ALLOW);
        }
    }

    @Test
    void rejectsValidSignedTokenWithoutRequiredScope(JenkinsRule jenkins) throws Exception {
        RSAKey rsaJwk = new RSAKeyGenerator(2048).keyID("kid-2").generate();
        String jwksJson = new JWKSet(rsaJwk.toPublicJWK()).toString();

        try (JwksServer jwksServer = JwksServer.start(jwksJson)) {
            String issuer = "https://issuer.example";
            String audience = "https://jenkins.example/mcp-server/mcp";

            McpOAuthConfiguration cfg = new McpOAuthConfiguration();
            cfg.setIssuer(issuer);
            cfg.setJwksUri(jwksServer.jwksUri());
            cfg.setRequiredScopes("mcp.build");

            String token = signToken(rsaJwk, issuer, audience, "mcp.read");
            TokenValidationResult result = McpBearerTokenValidator.validate(token, cfg, audience);

            assertThat(result.decision()).isEqualTo(TokenValidationResult.Decision.FORBIDDEN);
            assertThat(result.error()).isEqualTo("insufficient_scope");
        }
    }

    @Test
    void rejectsExpiredToken(JenkinsRule jenkins) throws Exception {
        RSAKey rsaJwk = new RSAKeyGenerator(2048).keyID("kid-expired").generate();
        String jwksJson = new JWKSet(rsaJwk.toPublicJWK()).toString();

        try (JwksServer jwksServer = JwksServer.start(jwksJson)) {
            String issuer = "https://issuer.example";
            String audience = "https://jenkins.example/mcp-server/mcp";

            McpOAuthConfiguration cfg = new McpOAuthConfiguration();
            cfg.setIssuer(issuer);
            cfg.setJwksUri(jwksServer.jwksUri());

            Instant now = Instant.now();
            String token = signToken(
                    rsaJwk,
                    issuer,
                    audience,
                    "user-1",
                    "mcp.read",
                    Date.from(now.minusSeconds(120)),
                    Date.from(now.minusSeconds(180)),
                    Date.from(now.minusSeconds(90)),
                    Map.of());

            TokenValidationResult result = McpBearerTokenValidator.validate(token, cfg, audience);

            assertThat(result.decision()).isEqualTo(TokenValidationResult.Decision.UNAUTHORIZED);
            assertThat(result.errorDescription()).contains("expired");
        }
    }

    @Test
    void rejectsTokenThatIsNotYetValid(JenkinsRule jenkins) throws Exception {
        RSAKey rsaJwk = new RSAKeyGenerator(2048).keyID("kid-nbf").generate();
        String jwksJson = new JWKSet(rsaJwk.toPublicJWK()).toString();

        try (JwksServer jwksServer = JwksServer.start(jwksJson)) {
            String issuer = "https://issuer.example";
            String audience = "https://jenkins.example/mcp-server/mcp";

            McpOAuthConfiguration cfg = new McpOAuthConfiguration();
            cfg.setIssuer(issuer);
            cfg.setJwksUri(jwksServer.jwksUri());

            Instant now = Instant.now();
            String token = signToken(
                    rsaJwk,
                    issuer,
                    audience,
                    "user-1",
                    "mcp.read",
                    Date.from(now.minusSeconds(5)),
                    Date.from(now.plusSeconds(180)),
                    Date.from(now.plusSeconds(300)),
                    Map.of());

            TokenValidationResult result = McpBearerTokenValidator.validate(token, cfg, audience);

            assertThat(result.decision()).isEqualTo(TokenValidationResult.Decision.UNAUTHORIZED);
            assertThat(result.errorDescription()).contains("not valid yet");
        }
    }

    @Test
    void reusesCachedJwksBetweenValidations(JenkinsRule jenkins) throws Exception {
        RSAKey rsaJwk = new RSAKeyGenerator(2048).keyID("kid-cache").generate();
        String jwksJson = new JWKSet(rsaJwk.toPublicJWK()).toString();

        try (JwksServer jwksServer = JwksServer.start(jwksJson)) {
            String issuer = "https://issuer.example";
            String audience = "https://jenkins.example/mcp-server/mcp";

            McpOAuthConfiguration cfg = new McpOAuthConfiguration();
            cfg.setIssuer(issuer);
            cfg.setJwksUri(jwksServer.jwksUri());
            cfg.setRequiredScopes("mcp.read");

            String token = signToken(rsaJwk, issuer, audience, "mcp.read");
            TokenValidationResult result1 = McpBearerTokenValidator.validate(token, cfg, audience);
            TokenValidationResult result2 = McpBearerTokenValidator.validate(token, cfg, audience);

            assertThat(result1.decision()).isEqualTo(TokenValidationResult.Decision.ALLOW);
            assertThat(result2.decision()).isEqualTo(TokenValidationResult.Decision.ALLOW);
            assertThat(jwksServer.requestCount().get()).isEqualTo(1);
        }
    }

    private static String signToken(RSAKey privateJwk, String issuer, String audience, String scopes)
            throws JOSEException {
        Instant now = Instant.now();
        return signToken(
            privateJwk,
            issuer,
            audience,
            "user-1",
            scopes,
            Date.from(now.minusSeconds(5)),
            Date.from(now.minusSeconds(5)),
            Date.from(now.plusSeconds(300)),
            Map.of());
        }

        private static String signToken(
            RSAKey privateJwk,
            String issuer,
            String audience,
            String subject,
            String scopes,
            Date issueTime,
            Date notBefore,
            Date expiration,
            Map<String, Object> extraClaims)
            throws JOSEException {
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
            .issuer(issuer)
            .audience(audience)
            .subject(subject)
            .claim("scope", scopes)
            .issueTime(issueTime)
            .notBeforeTime(notBefore)
            .expirationTime(expiration);

        for (Map.Entry<String, Object> entry : extraClaims.entrySet()) {
            claimsBuilder.claim(entry.getKey(), entry.getValue());
        }

        JWTClaimsSet claimsSet = claimsBuilder.build();

        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(privateJwk.getKeyID()).type(JOSEObjectType.JWT).build(),
                claimsSet);
        jwt.sign(new RSASSASigner(privateJwk));
        return jwt.serialize();
    }

    private record JwksServer(HttpServer server, String jwksUri, AtomicInteger requestCount) implements AutoCloseable {

        static JwksServer start(String jwksJson) throws IOException {
            AtomicInteger requestCount = new AtomicInteger(0);
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/jwks", new JsonHandler(jwksJson, requestCount));
            server.start();

            String endpoint = "http://127.0.0.1:" + server.getAddress().getPort() + "/jwks";
            return new JwksServer(server, endpoint, requestCount);
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }

    private static class JsonHandler implements HttpHandler {
        private final byte[] body;
        private final AtomicInteger requestCount;

        JsonHandler(String json, AtomicInteger requestCount) {
            this.body = json.getBytes(StandardCharsets.UTF_8);
            this.requestCount = requestCount;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            requestCount.incrementAndGet();
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream outputStream = exchange.getResponseBody()) {
                outputStream.write(body);
            }
        }
    }
}