/*
 *  Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2new.introspect;

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;

public class IntrospectionResponse extends IdentityResponse {

    /*
     * REQUIRED. Boolean indicator of whether or not the presented token is currently active. The specifics of a token's
     * "active" state will vary depending on the implementation of the authorization server and the information it keeps
     * about its tokens, but a "true" value return for the "active" property will generally indicate that a given token
     * has been issued by this authorization server, has not been revoked by the resource owner, and is within its given
     * time window of validity (e.g., after its issuance time and before its expiration time). See Section 4 for
     * information on implementation of such checks.
     */
    boolean active;

    /*
     * OPTIONAL. A JSON string containing a space-separated list of scopes associated with this token, in the format
     * described in Section 3.3 of OAuth 2.0
     */
    private String scope;

    /*
     * OPTIONAL. Client identifier for the OAuth 2.0 client that requested this token.
     */
    private String clientId;

    /*
     * OPTIONAL. Human-readable identifier for the resource owner who authorized this token.
     */
    private String username;

    /*
     * OPTIONAL. Type of the token as defined in Section 5.1 of OAuth 2.0
     */
    private String tokenType;

    /*
     * OPTIONAL. Integer time-stamp, measured in the number of seconds since January 1 1970 UTC, indicating when this
     * token is not to be used before, as defined in JWT
     */
    private long nbf;

    /*
     * OPTIONAL. Service-specific string identifier or list of string identifiers representing the intended audience for
     * this token, as defined in JWT
     */
    private String aud;

    /*
     * OPTIONAL. String representing the issuer of this token, as defined in JWT
     */
    private String iss;

    /*
     * OPTIONAL. String identifier for the token, as defined in JWT
     */
    private String jti;

    /*
     * OPTIONAL. Subject of the token, as defined in JWT [RFC7519]. Usually a machine-readable identifier of the
     * resource owner who authorized this token.
     */
    private String sub;

    /*
     * OPTIONAL. Integer time-stamp, measured in the number of seconds since January 1 1970 UTC, indicating when this
     * token will expire, as defined in JWT
     */
    private long exp;

    /*
     * OPTIONAL. Integer time-stamp, measured in the number of seconds since January 1 1970 UTC, indicating when this
     * token was originally issued, as defined in JWT
     */
    private long iat;

    protected IntrospectionResponse(IdentityResponseBuilder builder) {
        super(builder);
        IntrospectionResponseBuilder introspectionResponseBuilder = (IntrospectionResponseBuilder)builder;
        this.active = introspectionResponseBuilder.active;
        this.aud = introspectionResponseBuilder.aud;
        this.clientId = introspectionResponseBuilder.clientId;
        this.exp = introspectionResponseBuilder.exp;
        this.iat = introspectionResponseBuilder.iat;
        this.iss = introspectionResponseBuilder.iss;
        this.jti = introspectionResponseBuilder.jti;
        this.nbf = introspectionResponseBuilder.nbf;
        this.scope = introspectionResponseBuilder.scope;
        this.sub = introspectionResponseBuilder.sub;
        this.tokenType = introspectionResponseBuilder.tokenType;
        this.username = introspectionResponseBuilder.username;
    }

    public boolean isActive() {
        return active;
    }

    public String getScope() {
        return scope;
    }

    public String getClientId() {
        return clientId;
    }

    public String getUsername() {
        return username;
    }

    public String getTokenType() {
        return tokenType;
    }

    public long getNbf() {
        return nbf;
    }

    public String getAud() {
        return aud;
    }

    public String getIss() {
        return iss;
    }

    public String getJti() {
        return jti;
    }

    public String getSub() {
        return sub;
    }

    public long getExp() {
        return exp;
    }

    public long getIat() {
        return iat;
    }

    public static class IntrospectionResponseBuilder extends IdentityResponseBuilder {

        protected IntrospectionMessageContext messageContext;

        public IntrospectionResponseBuilder(IntrospectionMessageContext messageContext) {
            super(messageContext);
            this.messageContext = messageContext;
        }

        boolean active;
        private String scope;
        private String clientId;
        private String username;
        private String tokenType;
        private long nbf;
        private String aud;
        private String iss;
        private String jti;
        private String sub;
        private long exp;
        private long iat;

        public IntrospectionResponseBuilder setActive(boolean active) {
            this.active = active;
            return this;
        }

        public IntrospectionResponseBuilder setScope(String scope) {
            this.scope = scope;
            return this;
        }

        public IntrospectionResponseBuilder setClientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public IntrospectionResponseBuilder setUsername(String username) {
            this.username = username;
            return this;
        }

        public IntrospectionResponseBuilder setTokenType(String tokenType) {
            this.tokenType = tokenType;
            return this;
        }

        public IntrospectionResponseBuilder setNbf(long nbf) {
            this.nbf = nbf;
            return this;
        }

        public IntrospectionResponseBuilder setAud(String aud) {
            this.aud = aud;
            return this;
        }

        public IntrospectionResponseBuilder setIss(String iss) {
            this.iss = iss;
            return this;
        }

        public IntrospectionResponseBuilder setJti(String jti) {
            this.jti = jti;
            return this;
        }

        public IntrospectionResponseBuilder setSub(String sub) {
            this.sub = sub;
            return this;
        }

        public IntrospectionResponseBuilder setExp(long exp) {
            this.exp = exp;
            return this;
        }

        public IntrospectionResponseBuilder setIat(long iat) {
            this.iat = iat;
            return this;
        }

        public IntrospectionResponse build() {
            return new IntrospectionResponse(this);
        }
    }
}
