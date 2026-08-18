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

package io.jenkins.plugins.mcp.server;

import static org.assertj.core.api.Assertions.assertThat;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
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
import io.jenkins.plugins.mcp.server.auth.McpBearerTokenValidator;
import io.jenkins.plugins.mcp.server.auth.McpOAuthConfiguration;
import io.jenkins.plugins.mcp.server.junit.StatelessMcpTestClient;
import io.jenkins.plugins.mcp.server.junit.JenkinsStreamableMcpClientBuilder;
import io.modelcontextprotocol.spec.McpSchema;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import org.htmlunit.HttpMethod;
import org.htmlunit.WebRequest;
import org.htmlunit.WebResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class OAuthJwtEnforcementIntegrationTest {

    @AfterEach
    void cleanupConfig() {
        McpOAuthConfiguration cfg = McpOAuthConfiguration.get();
        cfg.setEnabled(false);
        cfg.setIssuer(null);
        cfg.setJwksUri(null);
        cfg.setAudience(null);
        cfg.setRequiredScopes(null);
        Endpoint.FORCE_OAUTH_ENFORCEMENT = false;
        McpBearerTokenValidator.resetCacheForTests();
    }

    @Test
    void validTokenAllowsRequest(JenkinsRule jenkins) throws Exception {
        RSAKey key = new RSAKeyGenerator(2048).keyID("kid-valid").generate();
        try (JwksServer jwks = JwksServer.start(new JWKSet(key.toPublicJWK()).toString())) {
            String issuer = "https://issuer.example";
            String audience = "https://jenkins.example/mcp-server/mcp";

            configureOAuth(issuer, jwks.jwksUri(), audience, "mcp.read");
            String token = signToken(key, issuer, audience, "mcp.read");

            WebResponse response = callMetrics(jenkins, token);
            assertThat(response.getStatusCode()).isEqualTo(HttpServletResponse.SC_OK);
        }
    }

    @Test
    void wrongAudienceGetsUnauthorized(JenkinsRule jenkins) throws Exception {
        RSAKey key = new RSAKeyGenerator(2048).keyID("kid-aud").generate();
        try (JwksServer jwks = JwksServer.start(new JWKSet(key.toPublicJWK()).toString())) {
            String issuer = "https://issuer.example";
            String configuredAudience = "https://jenkins.example/mcp-server/mcp";

            configureOAuth(issuer, jwks.jwksUri(), configuredAudience, "mcp.read");
            String token = signToken(key, issuer, "https://other.example/mcp", "mcp.read");

            WebResponse response = callMetrics(jenkins, token);
            assertThat(response.getStatusCode()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    @Test
    void missingRequiredScopeGetsForbidden(JenkinsRule jenkins) throws Exception {
        RSAKey key = new RSAKeyGenerator(2048).keyID("kid-scope").generate();
        try (JwksServer jwks = JwksServer.start(new JWKSet(key.toPublicJWK()).toString())) {
            String issuer = "https://issuer.example";
            String audience = "https://jenkins.example/mcp-server/mcp";

            configureOAuth(issuer, jwks.jwksUri(), audience, "mcp.build");
            String token = signToken(key, issuer, audience, "mcp.read");

            WebResponse response = callMetrics(jenkins, token);
            assertThat(response.getStatusCode()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
            assertThat(response.getResponseHeaderValue("WWW-Authenticate")).contains("insufficient_scope");
        }
    }

    @Test
    void mappedJwtIdentityIsUsedByToolExecution(JenkinsRule jenkins) throws Exception {
        RSAKey key = new RSAKeyGenerator(2048).keyID("kid-user").generate();
        try (JwksServer jwks = JwksServer.start(new JWKSet(key.toPublicJWK()).toString())) {
            String issuer = "https://issuer.example";
            String audience = "https://jenkins.example/mcp-server/mcp";
            String expectedUsername = "oauth-claim-user";

            McpOAuthConfiguration cfg = McpOAuthConfiguration.get();
            cfg.setEnabled(true);
            cfg.setIssuer(issuer);
            cfg.setJwksUri(jwks.jwksUri());
            cfg.setAudience(audience);
            cfg.setRequiredScopes("mcp.read");
            cfg.setUsernameClaim("preferred_username");

            String token = signToken(
                    key,
                    issuer,
                    audience,
                    "fallback-subject",
                    "mcp.read",
                    Map.of("preferred_username", expectedUsername));

            try (var client = new JenkinsStreamableMcpClientBuilder()
                    .jenkins(jenkins)
                    .requestCustomizer(builder -> builder.header("Authorization", "Bearer " + token))
                    .build()) {

                McpSchema.CallToolResult response =
                        client.callTool(new McpSchema.CallToolRequest("whoAmI", Map.of()));
                assertThat(response.isError()).isFalse();
                assertThat(response.content()).hasSize(1);
                assertThat(response.content().get(0).type()).isEqualTo("text");

                response.content().stream()
                        .filter(McpSchema.TextContent.class::isInstance)
                        .map(McpSchema.TextContent.class::cast)
                        .findFirst()
                        .ifPresent(textContent -> {
                            DocumentContext documentContext = JsonPath.using(Configuration.defaultConfiguration())
                                    .parse(textContent.text());
                            assertThat(documentContext.read("$.result.fullName", String.class))
                                    .isEqualTo(expectedUsername);
                        });
            }
        }
    }

    @Test
    void mappedJwtIdentityIsUsedByStatelessToolExecution(JenkinsRule jenkins) throws Exception {
        RSAKey key = new RSAKeyGenerator(2048).keyID("kid-user-stateless").generate();
        try (JwksServer jwks = JwksServer.start(new JWKSet(key.toPublicJWK()).toString())) {
            String issuer = "https://issuer.example";
            String audience = "https://jenkins.example/mcp-server/mcp";
            String expectedUsername = "oauth-claim-user-stateless";

            McpOAuthConfiguration cfg = McpOAuthConfiguration.get();
            cfg.setEnabled(true);
            cfg.setIssuer(issuer);
            cfg.setJwksUri(jwks.jwksUri());
            cfg.setAudience(audience);
            cfg.setRequiredScopes("mcp.read");
            cfg.setUsernameClaim("preferred_username");

            String token = signToken(
                    key,
                    issuer,
                    audience,
                    "fallback-subject",
                    "mcp.read",
                    Map.of("preferred_username", expectedUsername));

            try (StatelessMcpTestClient client =
                    new StatelessMcpTestClient(jenkins, builder -> builder.header("Authorization", "Bearer " + token))) {
                McpSchema.CallToolResult response = client.callTool("whoAmI", Map.of());
                assertThat(response.isError()).isFalse();
                assertThat(response.content()).hasSize(1);
                assertThat(response.content().get(0).type()).isEqualTo("text");

                response.content().stream()
                        .filter(McpSchema.TextContent.class::isInstance)
                        .map(McpSchema.TextContent.class::cast)
                        .findFirst()
                        .ifPresent(textContent -> {
                            DocumentContext documentContext = JsonPath.using(Configuration.defaultConfiguration())
                                    .parse(textContent.text());
                            assertThat(documentContext.read("$.result.fullName", String.class))
                                    .isEqualTo(expectedUsername);
                        });
            }
        }
    }

    private static void configureOAuth(String issuer, String jwksUri, String audience, String requiredScopes) {
        McpOAuthConfiguration cfg = McpOAuthConfiguration.get();
        cfg.setEnabled(true);
        cfg.setIssuer(issuer);
        cfg.setJwksUri(jwksUri);
        cfg.setAudience(audience);
        cfg.setRequiredScopes(requiredScopes);
    }

    private static WebResponse callMetrics(JenkinsRule jenkins, String token) throws Exception {
        try (JenkinsRule.WebClient webClient = jenkins.createWebClient()) {
            webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
            String endpointUrl = jenkins.getURL() + McpConnectionMetrics.URL_NAME;
            WebRequest request = new WebRequest(new URL(endpointUrl), HttpMethod.GET);
            request.setAdditionalHeader("Authorization", "Bearer " + token);
            return webClient.loadWebResponse(request);
        }
    }

    private static String signToken(RSAKey privateJwk, String issuer, String audience, String scopes) throws Exception {
        return signToken(privateJwk, issuer, audience, "oauth-user", scopes, Map.of());
    }

    private static String signToken(
            RSAKey privateJwk,
            String issuer,
            String audience,
            String subject,
            String scopes,
            Map<String, Object> extraClaims)
            throws Exception {
        Instant now = Instant.now();
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(audience)
                .subject(subject)
                .claim("scope", scopes)
                .issueTime(Date.from(now.minusSeconds(5)))
                .notBeforeTime(Date.from(now.minusSeconds(5)))
                .expirationTime(Date.from(now.plusSeconds(300)));

        for (Map.Entry<String, Object> claim : extraClaims.entrySet()) {
            builder.claim(claim.getKey(), claim.getValue());
        }

        JWTClaimsSet claimsSet = builder.build();

        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(privateJwk.getKeyID()).type(JOSEObjectType.JWT).build(),
                claimsSet);
        jwt.sign(new RSASSASigner(privateJwk));
        return jwt.serialize();
    }

    private record JwksServer(HttpServer server, String jwksUri) implements AutoCloseable {

        static JwksServer start(String jwksJson) throws IOException {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/jwks", new JsonHandler(jwksJson));
            server.start();
            return new JwksServer(server, "http://127.0.0.1:" + server.getAddress().getPort() + "/jwks");
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }

    private static class JsonHandler implements HttpHandler {
        private final byte[] body;

        JsonHandler(String json) {
            this.body = json.getBytes(StandardCharsets.UTF_8);
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream outputStream = exchange.getResponseBody()) {
                outputStream.write(body);
            }
        }
    }
}