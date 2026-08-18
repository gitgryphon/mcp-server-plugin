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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import hudson.Extension;
import hudson.model.UnprotectedRootAction;
import io.jenkins.plugins.mcp.server.Endpoint;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import jenkins.model.Jenkins;
import jenkins.model.JenkinsLocationConfiguration;
import org.apache.commons.lang3.StringUtils;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.StaplerResponse2;

/**
 * RFC9728 protected resource metadata endpoint for MCP OAuth discovery.
 *
 * <p><b>Known limitation:</b> this action claims the {@code .well-known} URL space as a Jenkins
 * root action. If a peer plugin such as
 * <a href="https://plugins.jenkins.io/oidc-provider/">oidc-provider</a> is installed and also
 * registers a {@code .well-known} root action, only one wins the dispatch slot. In that scenario,
 * disable OAuth enforcement or omit this plugin from OAuth duties so the peer's discovery
 * endpoints (e.g. {@code openid-configuration}, {@code jwks}) are reachable.
 */
@Restricted(NoExternalUse.class)
@Extension
public class OAuthProtectedResourceMetadataEndpoint implements UnprotectedRootAction {

    static final String URL_NAME = ".well-known/oauth-protected-resource";
    private static final String ROOT_URL_NAME = ".well-known";
    private static final String RESOURCE_SEGMENT = "/oauth-protected-resource";

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Override
    public String getIconFileName() {
        return null;
    }

    @Override
    public String getDisplayName() {
        return null;
    }

    @Override
    public String getUrlName() {
        return ROOT_URL_NAME;
    }

    public void doIndex(StaplerRequest2 req, StaplerResponse2 rsp) throws IOException {
        rsp.sendError(HttpServletResponse.SC_NOT_FOUND);
    }

    public void doDynamic(StaplerRequest2 req, StaplerResponse2 rsp) throws IOException {
        if (RESOURCE_SEGMENT.equals(req.getRestOfPath())) {
            handleMetadataRequest(rsp);
            return;
        }
        rsp.sendError(HttpServletResponse.SC_NOT_FOUND);
    }

    public static void handleMetadataRequest(HttpServletResponse response) throws IOException {
        McpOAuthConfiguration configuration = McpOAuthConfiguration.get();
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(OBJECT_MAPPER.writeValueAsString(buildMetadata(configuration)));
        response.getWriter().flush();
    }

    static ObjectNode buildMetadata(McpOAuthConfiguration configuration) {
        ObjectNode metadata = OBJECT_MAPPER.createObjectNode();
        String resource = canonicalResourceUri(configuration);
        metadata.put("resource", resource);

        ArrayNode authorizationServers = metadata.putArray("authorization_servers");
        List<String> configuredServers = configuration.getAuthorizationServers();
        if (configuredServers.isEmpty()) {
            String issuer = StringUtils.trimToNull(configuration.getIssuer());
            if (issuer != null) {
                authorizationServers.add(issuer);
            }
        } else {
            configuredServers.forEach(authorizationServers::add);
        }

        ArrayNode bearerMethods = metadata.putArray("bearer_methods_supported");
        bearerMethods.add("header");

        String scopes = StringUtils.trimToNull(configuration.getRequiredScopes());
        if (scopes != null) {
            ArrayNode scopeArray = metadata.putArray("scopes_supported");
            for (String scope : scopes.split("\\s+")) {
                if (!scope.isBlank()) {
                    scopeArray.add(scope);
                }
            }
        }

        String jwksUri = StringUtils.trimToNull(configuration.getJwksUri());
        if (jwksUri != null) {
            metadata.put("jwks_uri", jwksUri);
        }

        return metadata;
    }

    private static String canonicalResourceUri(McpOAuthConfiguration configuration) {
        String configuredAudience = StringUtils.trimToNull(configuration.getAudience());
        if (configuredAudience != null) {
            return configuredAudience;
        }

        String rootUrl = StringUtils.trimToNull(JenkinsLocationConfiguration.get().getUrl());
        if (rootUrl != null) {
            return StringUtils.removeEnd(rootUrl, "/") + "/" + Endpoint.MCP_SERVER_STREAMABLE;
        }

        String fallback = StringUtils.trimToNull(Jenkins.get().getRootUrl());
        if (fallback != null) {
            return StringUtils.removeEnd(fallback, "/") + "/" + Endpoint.MCP_SERVER_STREAMABLE;
        }

        return Endpoint.MCP_SERVER_STREAMABLE;
    }
}