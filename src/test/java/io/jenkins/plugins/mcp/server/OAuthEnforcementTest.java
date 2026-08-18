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

import io.jenkins.plugins.mcp.server.auth.McpOAuthConfiguration;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URL;
import org.htmlunit.HttpMethod;
import org.htmlunit.WebRequest;
import org.htmlunit.WebResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class OAuthEnforcementTest {

    @AfterEach
    void resetOAuthFlag() {
        McpOAuthConfiguration cfg = McpOAuthConfiguration.get();
        cfg.setEnabled(false);
        cfg.setTrustUpstreamAuthentication(false);
        Endpoint.FORCE_OAUTH_ENFORCEMENT = false;
    }

    @Test
    void mcpRequestWithoutBearerReturns401WithResourceMetadata(JenkinsRule jenkins) throws Exception {
        Endpoint.FORCE_OAUTH_ENFORCEMENT = true;
        try (JenkinsRule.WebClient webClient = jenkins.createWebClient()) {
            webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
            String endpointUrl = jenkins.getURL() + McpConnectionMetrics.URL_NAME;

            WebResponse response = webClient.loadWebResponse(new WebRequest(new URL(endpointUrl), HttpMethod.GET));

            assertThat(response.getStatusCode()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
            String challenge = response.getResponseHeaderValue("WWW-Authenticate");
            assertThat(challenge).contains("Bearer");
            assertThat(challenge).contains("resource_metadata=");
            assertThat(challenge).contains("/.well-known/oauth-protected-resource");
        }
    }

    @Test
    void mcpRequestWithBearerAndIncompleteConfigReturns500(JenkinsRule jenkins) throws Exception {
        Endpoint.FORCE_OAUTH_ENFORCEMENT = true;
        try (JenkinsRule.WebClient webClient = jenkins.createWebClient()) {
            webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
            String endpointUrl = jenkins.getURL() + McpConnectionMetrics.URL_NAME;

            WebRequest request = new WebRequest(new URL(endpointUrl), HttpMethod.GET);
            request.setAdditionalHeader("Authorization", "Bearer test-token");
            WebResponse response = webClient.loadWebResponse(request);

            // Force mode should still fail closed when OAuth validation settings are incomplete.
            assertThat(response.getStatusCode()).isEqualTo(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    @Test
    void trustUpstreamAuthenticationStillRejectsAnonymousBearer(JenkinsRule jenkins) throws Exception {
        Endpoint.FORCE_OAUTH_ENFORCEMENT = true;
        McpOAuthConfiguration.get().setTrustUpstreamAuthentication(true);

        try (JenkinsRule.WebClient webClient = jenkins.createWebClient()) {
            webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
            String endpointUrl = jenkins.getURL() + McpConnectionMetrics.URL_NAME;

            WebRequest request = new WebRequest(new URL(endpointUrl), HttpMethod.GET);
            request.setAdditionalHeader("Authorization", "Bearer bogus-token");
            WebResponse response = webClient.loadWebResponse(request);

            // No upstream principal (anonymous) — trust-upstream must not bypass, so validation runs
            // and fails with 500 due to no OAuth configuration.
            assertThat(response.getStatusCode()).isEqualTo(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }
}