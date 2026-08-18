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

import hudson.util.FormValidation;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class McpOAuthConfigurationTest {

    @Test
    void defaultsAreSafeAndDisabled(JenkinsRule jenkins) {
        McpOAuthConfiguration config = new McpOAuthConfiguration();

        assertThat(config.isEnabled()).isFalse();
        assertThat(config.getIssuer()).isNull();
        assertThat(config.getJwksUri()).isNull();
        assertThat(config.getAudience()).isNull();
        assertThat(config.getUsernameClaim()).isEqualTo("sub");
        assertThat(config.getGroupsClaim()).isNull();
        assertThat(config.getRequiredScopes()).isNull();
        assertThat(config.getAuthorizationServers()).isEmpty();
    }

    @Test
    void settersTrimAndNormalizeValues(JenkinsRule jenkins) {
        McpOAuthConfiguration config = new McpOAuthConfiguration();

        config.setIssuer("  https://issuer.example  ");
        config.setJwksUri(" https://issuer.example/jwks ");
        config.setAudience(" https://jenkins.example/mcp-server/mcp ");
        config.setUsernameClaim("   ");
        config.setGroupsClaim(" groups ");
        config.setRequiredScopes(" mcp.read mcp.build ");
        config.setAuthorizationServersText("https://as1.example\nhttps://as2.example, https://as1.example ");

        assertThat(config.getIssuer()).isEqualTo("https://issuer.example");
        assertThat(config.getJwksUri()).isEqualTo("https://issuer.example/jwks");
        assertThat(config.getAudience()).isEqualTo("https://jenkins.example/mcp-server/mcp");
        assertThat(config.getUsernameClaim()).isEqualTo("sub");
        assertThat(config.getGroupsClaim()).isEqualTo("groups");
        assertThat(config.getRequiredScopes()).isEqualTo("mcp.read mcp.build");
        assertThat(config.getAuthorizationServers()).isEqualTo(List.of("https://as1.example", "https://as2.example"));
    }

    @Test
    void httpsChecksAllowLocalhostAndRejectNonHttpsRemote(JenkinsRule jenkins) {
        McpOAuthConfiguration config = new McpOAuthConfiguration();

        FormValidation localIssuer = config.doCheckIssuer("http://localhost:8080");
        FormValidation localJwks = config.doCheckJwksUri("http://127.0.0.1:9000/jwks");
        FormValidation remoteIssuer = config.doCheckIssuer("http://issuer.example");
        FormValidation remoteJwks = config.doCheckJwksUri("http://issuer.example/jwks");

        assertThat(localIssuer.kind).isEqualTo(FormValidation.Kind.OK);
        assertThat(localJwks.kind).isEqualTo(FormValidation.Kind.OK);
        assertThat(remoteIssuer.kind).isEqualTo(FormValidation.Kind.ERROR);
        assertThat(remoteJwks.kind).isEqualTo(FormValidation.Kind.ERROR);
    }

    @Test
    void trustUpstreamAuthenticationDefaultsOffAndIsPersistable(JenkinsRule jenkins) {
        McpOAuthConfiguration config = new McpOAuthConfiguration();
        assertThat(config.isTrustUpstreamAuthentication()).isFalse();

        config.setTrustUpstreamAuthentication(true);
        assertThat(config.isTrustUpstreamAuthentication()).isTrue();

        config.setTrustUpstreamAuthentication(false);
        assertThat(config.isTrustUpstreamAuthentication()).isFalse();
    }
}