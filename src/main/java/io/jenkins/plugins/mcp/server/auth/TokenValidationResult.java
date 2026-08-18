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

import java.util.Objects;

public class TokenValidationResult {

    public enum Decision {
        ALLOW,
        UNAUTHORIZED,
        FORBIDDEN,
        SERVER_ERROR
    }

    private final Decision decision;
    private final String error;
    private final String errorDescription;
    private final String requiredScope;

    private TokenValidationResult(Decision decision, String error, String errorDescription, String requiredScope) {
        this.decision = Objects.requireNonNull(decision);
        this.error = error;
        this.errorDescription = errorDescription;
        this.requiredScope = requiredScope;
    }

    public static TokenValidationResult allow() {
        return new TokenValidationResult(Decision.ALLOW, null, null, null);
    }

    public static TokenValidationResult unauthorized(String error, String errorDescription) {
        return new TokenValidationResult(Decision.UNAUTHORIZED, error, errorDescription, null);
    }

    public static TokenValidationResult forbiddenInsufficientScope(String requiredScope) {
        return new TokenValidationResult(
                Decision.FORBIDDEN,
                "insufficient_scope",
                "Token does not include all required scopes",
                requiredScope);
    }

    public static TokenValidationResult serverError(String errorDescription) {
        return new TokenValidationResult(Decision.SERVER_ERROR, "server_error", errorDescription, null);
    }

    public Decision decision() {
        return decision;
    }

    public String error() {
        return error;
    }

    public String errorDescription() {
        return errorDescription;
    }

    public String requiredScope() {
        return requiredScope;
    }
}