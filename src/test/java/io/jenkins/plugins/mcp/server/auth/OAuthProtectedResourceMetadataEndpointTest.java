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

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URL;
import org.htmlunit.HttpMethod;
import org.htmlunit.WebRequest;
import org.htmlunit.WebResponse;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class OAuthProtectedResourceMetadataEndpointTest {

    @Test
    void metadataEndpointReturnsConfiguredFields(JenkinsRule jenkins) throws Exception {
        McpOAuthConfiguration configuration = McpOAuthConfiguration.get();
        configuration.setIssuer("https://issuer.example");
        configuration.setJwksUri("https://issuer.example/.well-known/jwks.json");
        configuration.setAudience("https://jenkins.example/mcp-server/mcp");
        configuration.setRequiredScopes("mcp.read mcp.build");
        configuration.setAuthorizationServersText("https://as1.example\nhttps://as2.example");

        try (JenkinsRule.WebClient webClient = jenkins.createWebClient()) {
            String metadataUrl = jenkins.getURL() + OAuthProtectedResourceMetadataEndpoint.URL_NAME;
            WebResponse response = webClient.loadWebResponse(new WebRequest(new URL(metadataUrl), HttpMethod.GET));

            assertThat(response.getStatusCode()).isEqualTo(HttpServletResponse.SC_OK);
            assertThat(response.getContentType()).contains("application/json");

            DocumentContext json = JsonPath.parse(response.getContentAsString());
            assertThat(json.read("$.resource", String.class)).isEqualTo("https://jenkins.example/mcp-server/mcp");
            assertThat(json.read("$.jwks_uri", String.class)).isEqualTo("https://issuer.example/.well-known/jwks.json");
            assertThat(json.read("$.authorization_servers[0]", String.class)).isEqualTo("https://as1.example");
            assertThat(json.read("$.authorization_servers[1]", String.class)).isEqualTo("https://as2.example");
            assertThat(json.read("$.bearer_methods_supported[0]", String.class)).isEqualTo("header");
            assertThat(json.read("$.scopes_supported[0]", String.class)).isEqualTo("mcp.read");
            assertThat(json.read("$.scopes_supported[1]", String.class)).isEqualTo("mcp.build");
        }
    }

    @Test
    void metadataEndpointAccessibleWithoutAuthentication(JenkinsRule jenkins) throws Exception {
        jenkins.jenkins.setSecurityRealm(jenkins.createDummySecurityRealm());

        try (JenkinsRule.WebClient webClient = jenkins.createWebClient()) {
            webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
            String metadataUrl = jenkins.getURL() + OAuthProtectedResourceMetadataEndpoint.URL_NAME;
            WebResponse response = webClient.loadWebResponse(new WebRequest(new URL(metadataUrl), HttpMethod.GET));
            assertThat(response.getStatusCode()).isEqualTo(HttpServletResponse.SC_OK);
        }
    }
}