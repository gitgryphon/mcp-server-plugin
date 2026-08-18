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

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public final class McpJwtAuthenticationMapper {

    private McpJwtAuthenticationMapper() {}

    public static Authentication fromValidatedToken(String token, McpOAuthConfiguration configuration) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            JWTClaimsSet claims = jwt.getJWTClaimsSet();

            String usernameClaim = StringUtils.defaultIfBlank(configuration.getUsernameClaim(), "sub");
            String username = StringUtils.trimToNull(claimValueAsString(claims.getClaim(usernameClaim)));
            if (username == null) {
                username = StringUtils.trimToNull(claims.getSubject());
            }
            if (username == null) {
                username = "mcp-user";
            }

            List<GrantedAuthority> authorities = mapAuthorities(claims, configuration.getGroupsClaim());
            return UsernamePasswordAuthenticationToken.authenticated(username, "N/A", authorities);
        } catch (ParseException e) {
            return null;
        }
    }

    private static List<GrantedAuthority> mapAuthorities(JWTClaimsSet claims, String groupsClaimName) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        if (StringUtils.isBlank(groupsClaimName)) {
            return authorities;
        }

        Object groupsClaim = claims.getClaim(groupsClaimName);
        if (groupsClaim instanceof Collection<?> collection) {
            for (Object item : collection) {
                String value = StringUtils.trimToNull(item != null ? item.toString() : null);
                if (value != null) {
                    authorities.add(new SimpleGrantedAuthority(toAuthority(value)));
                }
            }
        } else if (groupsClaim instanceof String str) {
            for (String token : str.split("[,\\s]+")) {
                String value = StringUtils.trimToNull(token);
                if (value != null) {
                    authorities.add(new SimpleGrantedAuthority(toAuthority(value)));
                }
            }
        }
        return authorities;
    }

    private static String toAuthority(String value) {
        return value.startsWith("ROLE_") ? value : "ROLE_" + value;
    }

    private static String claimValueAsString(Object value) {
        return value != null ? value.toString() : null;
    }
}