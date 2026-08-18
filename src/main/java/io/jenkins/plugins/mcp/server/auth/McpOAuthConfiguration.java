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

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.util.FormValidation;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.stream.Collectors;
import jenkins.model.GlobalConfiguration;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

/**
 * Global OAuth 2.1 resource-server settings for MCP HTTP endpoints.
 *
 * <p>This class is intentionally config-only at this stage; request-time auth checks are wired separately.
 */
@Extension
@Symbol("mcpOAuth")
public class McpOAuthConfiguration extends GlobalConfiguration {

    private static volatile McpOAuthConfiguration fallbackInstance;

    private boolean enabled;
    private boolean trustUpstreamAuthentication;
    private String issuer;
    private String jwksUri;
    private String audience;
    private String usernameClaim = "sub";
    private String groupsClaim;
    private String requiredScopes;
    private List<String> authorizationServers = List.of();

    public McpOAuthConfiguration() {
        load();
    }

    public static @NonNull McpOAuthConfiguration get() {
        McpOAuthConfiguration config = GlobalConfiguration.all().get(McpOAuthConfiguration.class);
        if (config != null) {
            return config;
        }

        // Fallback for test harnesses where extension indexing may not have loaded this class yet.
        if (fallbackInstance == null) {
            synchronized (McpOAuthConfiguration.class) {
                if (fallbackInstance == null) {
                    fallbackInstance = new McpOAuthConfiguration();
                }
            }
        }
        return fallbackInstance;
    }

    public boolean isEnabled() {
        return enabled;
    }

    @DataBoundSetter
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
        save();
    }

    /**
     * When {@code true} and the request already has an authenticated Jenkins user
     * (e.g. established by the jwt-auth plugin or another security realm), the MCP OAuth
     * gate skips its own JWT validation and reuses the existing identity. Only honored
     * when OAuth enforcement is otherwise active.
     */
    public boolean isTrustUpstreamAuthentication() {
        return trustUpstreamAuthentication;
    }

    @DataBoundSetter
    public void setTrustUpstreamAuthentication(boolean trustUpstreamAuthentication) {
        this.trustUpstreamAuthentication = trustUpstreamAuthentication;
        save();
    }

    public String getIssuer() {
        return issuer;
    }

    @DataBoundSetter
    public void setIssuer(String issuer) {
        this.issuer = StringUtils.trimToNull(issuer);
        save();
    }

    public String getJwksUri() {
        return jwksUri;
    }

    @DataBoundSetter
    public void setJwksUri(String jwksUri) {
        this.jwksUri = StringUtils.trimToNull(jwksUri);
        save();
    }

    public String getAudience() {
        return audience;
    }

    @DataBoundSetter
    public void setAudience(String audience) {
        this.audience = StringUtils.trimToNull(audience);
        save();
    }

    public String getUsernameClaim() {
        return usernameClaim;
    }

    @DataBoundSetter
    public void setUsernameClaim(String usernameClaim) {
        this.usernameClaim = StringUtils.defaultIfBlank(StringUtils.trim(usernameClaim), "sub");
        save();
    }

    public String getGroupsClaim() {
        return groupsClaim;
    }

    @DataBoundSetter
    public void setGroupsClaim(String groupsClaim) {
        this.groupsClaim = StringUtils.trimToNull(groupsClaim);
        save();
    }

    public String getRequiredScopes() {
        return requiredScopes;
    }

    @DataBoundSetter
    public void setRequiredScopes(String requiredScopes) {
        this.requiredScopes = StringUtils.trimToNull(requiredScopes);
        save();
    }

    public List<String> getAuthorizationServers() {
        return authorizationServers;
    }

    @DataBoundSetter
    public void setAuthorizationServers(List<String> authorizationServers) {
        this.authorizationServers = normalizeAuthorizationServers(authorizationServers);
        save();
    }

    /**
     * Supports simple text-based config.jelly binding where values come as comma/newline separated text.
     */
    @DataBoundSetter
    public void setAuthorizationServersText(String authorizationServersText) {
        if (StringUtils.isBlank(authorizationServersText)) {
            this.authorizationServers = List.of();
        } else {
            this.authorizationServers = normalizeAuthorizationServers(
                    Arrays.stream(authorizationServersText.split("[,\\r\\n]+"))
                            .collect(Collectors.toList()));
        }
        save();
    }

    public String getAuthorizationServersText() {
        return String.join("\n", authorizationServers);
    }

    private static List<String> normalizeAuthorizationServers(List<String> values) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        return values.stream()
                .map(StringUtils::trimToNull)
                .filter(Objects::nonNull)
                .distinct()
                .collect(Collectors.toList());
    }

    public FormValidation doCheckIssuer(@QueryParameter String value) {
        if (StringUtils.isBlank(value)) {
            return FormValidation.ok();
        }
        return validateSecureUrl(value, "Issuer");
    }

    public FormValidation doCheckJwksUri(@QueryParameter String value) {
        if (StringUtils.isBlank(value)) {
            return FormValidation.ok();
        }
        return validateSecureUrl(value, "JWKS URI");
    }

    private static FormValidation validateSecureUrl(String value, String fieldName) {
        String trimmed = StringUtils.trimToNull(value);
        if (trimmed == null) {
            return FormValidation.ok();
        }

        try {
            URI uri = new URI(trimmed);
            String scheme = StringUtils.trimToEmpty(uri.getScheme()).toLowerCase(Locale.ROOT);
            if ("https".equals(scheme)) {
                return FormValidation.ok();
            }
            if (!"http".equals(scheme)) {
                return FormValidation.error(fieldName + " must use https:// (or http://localhost for local test mode).");
            }

            String host = StringUtils.trimToNull(uri.getHost());
            if (host == null) {
                return FormValidation.error(fieldName + " must include a valid host.");
            }

            String normalized = host.toLowerCase(Locale.ROOT);
            if ("localhost".equals(normalized) || "127.0.0.1".equals(normalized) || "::1".equals(normalized)) {
                return FormValidation.ok();
            }

            try {
                InetAddress address = InetAddress.getByName(host);
                if (address.isLoopbackAddress()) {
                    return FormValidation.ok();
                }
            } catch (Exception ignored) {
                // Fall through to error.
            }

            return FormValidation.error(fieldName + " must use https:// in non-local environments.");
        } catch (URISyntaxException e) {
            return FormValidation.error(fieldName + " is not a valid URI.");
        }
    }
}