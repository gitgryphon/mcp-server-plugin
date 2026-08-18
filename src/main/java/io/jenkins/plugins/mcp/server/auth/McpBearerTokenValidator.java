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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;

public final class McpBearerTokenValidator {

    private static final Duration CLOCK_SKEW = Duration.ofSeconds(60);
    private static final Duration JWKS_CACHE_TTL = Duration.ofMinutes(5);

    private static volatile CachedJwkSet cachedJwkSet;

    private McpBearerTokenValidator() {}

    public static TokenValidationResult validate(
            String token, McpOAuthConfiguration configuration, String expectedAudience) {
        String issuer = StringUtils.trimToNull(configuration.getIssuer());
        String jwksUri = StringUtils.trimToNull(configuration.getJwksUri());
        String audience = StringUtils.trimToNull(expectedAudience);

        if (issuer == null || jwksUri == null || audience == null) {
            return TokenValidationResult.serverError(
                    "OAuth configuration is incomplete: issuer, jwksUri and audience are required");
        }

        if (!isHttpsOrLocalTestUrl(issuer)) {
            return TokenValidationResult.serverError(
                "Insecure OAuth configuration: issuer must use https:// unless host is localhost/loopback");
        }
        if (!isHttpsOrLocalTestUrl(jwksUri)) {
            return TokenValidationResult.serverError(
                "Insecure OAuth configuration: jwksUri must use https:// unless host is localhost/loopback");
        }

        SignedJWT signedJwt;
        try {
            signedJwt = SignedJWT.parse(token);
        } catch (ParseException e) {
            return TokenValidationResult.unauthorized("invalid_token", "Token is not a valid signed JWT");
        }

        if (!isAllowedAlgorithm(signedJwt.getHeader().getAlgorithm())) {
            return TokenValidationResult.unauthorized("invalid_token", "Unsupported or insecure JWT algorithm");
        }

        JWKSet jwkSet;
        try {
            jwkSet = fetchJwkSet(jwksUri);
        } catch (IOException | InterruptedException | ParseException | URISyntaxException e) {
            return TokenValidationResult.serverError("Failed to fetch or parse JWKS");
        }

        if (!verifySignature(signedJwt, jwkSet)) {
            return TokenValidationResult.unauthorized("invalid_token", "JWT signature validation failed");
        }

        JWTClaimsSet claims;
        try {
            claims = signedJwt.getJWTClaimsSet();
        } catch (ParseException e) {
            return TokenValidationResult.unauthorized("invalid_token", "Unable to parse JWT claims");
        }

        TokenValidationResult claimValidation = validateClaims(claims, issuer, audience);
        if (claimValidation.decision() != TokenValidationResult.Decision.ALLOW) {
            return claimValidation;
        }

        Set<String> requiredScopes = parseRequiredScopes(configuration.getRequiredScopes());
        if (!requiredScopes.isEmpty()) {
            Set<String> tokenScopes = parseTokenScopes(claims);
            if (!tokenScopes.containsAll(requiredScopes)) {
                String requiredScopeText = requiredScopes.stream().sorted().collect(Collectors.joining(" "));
                return TokenValidationResult.forbiddenInsufficientScope(requiredScopeText);
            }
        }

        return TokenValidationResult.allow();
    }

    private static boolean isAllowedAlgorithm(JWSAlgorithm algorithm) {
        if (algorithm == null || JWSAlgorithm.NONE.equals(algorithm)) {
            return false;
        }
        String name = algorithm.getName().toUpperCase(Locale.ROOT);
        return name.startsWith("RS") || name.startsWith("PS") || name.startsWith("ES");
    }

    private static JWKSet fetchJwkSet(String jwksUri)
            throws IOException, InterruptedException, ParseException, URISyntaxException {
        CachedJwkSet localCache = cachedJwkSet;
        Instant now = Instant.now();
        if (localCache != null
                && localCache.jwksUri().equals(jwksUri)
                && now.isBefore(localCache.expiresAt())) {
            return localCache.jwkSet();
        }

        synchronized (McpBearerTokenValidator.class) {
            localCache = cachedJwkSet;
            now = Instant.now();
            if (localCache != null
                    && localCache.jwksUri().equals(jwksUri)
                    && now.isBefore(localCache.expiresAt())) {
                return localCache.jwkSet();
            }

            JWKSet fetched = fetchJwkSetRemote(jwksUri);
            cachedJwkSet = new CachedJwkSet(jwksUri, fetched, now.plus(JWKS_CACHE_TTL));
            return fetched;
        }
    }

    private static JWKSet fetchJwkSetRemote(String jwksUri)
            throws IOException, InterruptedException, ParseException, URISyntaxException {
        HttpRequest request = HttpRequest.newBuilder()
                .GET()
                .uri(new URI(jwksUri))
                .timeout(Duration.ofSeconds(10))
                .header("Accept", "application/json")
                .build();
        HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("JWKS endpoint returned status " + response.statusCode());
        }
        return JWKSet.parse(response.body());
    }

    public static void resetCacheForTests() {
        cachedJwkSet = null;
    }

    private static boolean isHttpsOrLocalTestUrl(String url) {
        try {
            URI uri = new URI(url);
            String scheme = StringUtils.trimToEmpty(uri.getScheme()).toLowerCase(Locale.ROOT);
            if ("https".equals(scheme)) {
                return true;
            }
            if (!"http".equals(scheme)) {
                return false;
            }

            String host = StringUtils.trimToNull(uri.getHost());
            if (host == null) {
                return false;
            }

            String normalized = host.toLowerCase(Locale.ROOT);
            if ("localhost".equals(normalized) || "127.0.0.1".equals(normalized) || "::1".equals(normalized)) {
                return true;
            }

            try {
                InetAddress address = InetAddress.getByName(host);
                return address.isLoopbackAddress();
            } catch (Exception ignored) {
                return false;
            }
        } catch (URISyntaxException e) {
            return false;
        }
    }

    private static boolean verifySignature(SignedJWT signedJwt, JWKSet jwkSet) {
        String keyId = signedJwt.getHeader().getKeyID();
        List<JWK> keys = jwkSet.getKeys().stream()
                .filter(k -> keyId == null || keyId.equals(k.getKeyID()))
                .toList();

        for (JWK jwk : keys) {
            JWSVerifier verifier = toVerifier(jwk, signedJwt.getHeader().getAlgorithm());
            if (verifier == null) {
                continue;
            }
            try {
                if (signedJwt.verify(verifier)) {
                    return true;
                }
            } catch (JOSEException ignored) {
                // Try next key.
            }
        }
        return false;
    }

    private static JWSVerifier toVerifier(JWK jwk, JWSAlgorithm algorithm) {
        String alg = algorithm != null ? algorithm.getName().toUpperCase(Locale.ROOT) : "";
        try {
            if ((alg.startsWith("RS") || alg.startsWith("PS")) && jwk instanceof RSAKey rsaKey) {
                return new RSASSAVerifier(rsaKey.toRSAPublicKey());
            }
            if (alg.startsWith("ES") && jwk instanceof ECKey ecKey) {
                return new ECDSAVerifier(ecKey.toECPublicKey());
            }
        } catch (JOSEException e) {
            return null;
        }
        return null;
    }

    private static TokenValidationResult validateClaims(JWTClaimsSet claims, String expectedIssuer, String expectedAudience) {
        if (!expectedIssuer.equals(claims.getIssuer())) {
            return TokenValidationResult.unauthorized("invalid_token", "Issuer claim does not match configuration");
        }

        List<String> audiences = claims.getAudience();
        if (audiences == null || !audiences.contains(expectedAudience)) {
            return TokenValidationResult.unauthorized("invalid_token", "Audience claim is not valid for this MCP server");
        }

        Instant now = Instant.now();
        Date expiration = claims.getExpirationTime();
        if (expiration == null || expiration.toInstant().isBefore(now.minus(CLOCK_SKEW))) {
            return TokenValidationResult.unauthorized("invalid_token", "Token is expired");
        }

        Date notBefore = claims.getNotBeforeTime();
        if (notBefore != null && notBefore.toInstant().isAfter(now.plus(CLOCK_SKEW))) {
            return TokenValidationResult.unauthorized("invalid_token", "Token is not valid yet");
        }

        return TokenValidationResult.allow();
    }

    private static Set<String> parseRequiredScopes(String requiredScopesText) {
        if (StringUtils.isBlank(requiredScopesText)) {
            return Set.of();
        }
        return List.of(requiredScopesText.trim().split("\\s+"))
                .stream()
                .filter(StringUtils::isNotBlank)
                .collect(Collectors.toCollection(HashSet::new));
    }

    private static Set<String> parseTokenScopes(JWTClaimsSet claims) {
        Set<String> scopes = new HashSet<>();

        Object scopeClaim = claims.getClaim("scope");
        if (scopeClaim instanceof String scopeString) {
            for (String scope : scopeString.trim().split("\\s+")) {
                if (!scope.isBlank()) {
                    scopes.add(scope);
                }
            }
        }

        Object scpClaim = claims.getClaim("scp");
        if (scpClaim instanceof String scpString) {
            for (String scope : scpString.trim().split("\\s+")) {
                if (!scope.isBlank()) {
                    scopes.add(scope);
                }
            }
        } else if (scpClaim instanceof Collection<?> scpCollection) {
            for (Object value : scpCollection) {
                if (value != null && StringUtils.isNotBlank(value.toString())) {
                    scopes.add(value.toString().trim());
                }
            }
        }

        return scopes;
    }

    private record CachedJwkSet(String jwksUri, JWKSet jwkSet, Instant expiresAt) {}
}