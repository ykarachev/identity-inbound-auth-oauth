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

package org.wso2.carbon.identity.oauth2new.revoke;

import org.wso2.carbon.identity.oauth2new.bean.message.request.OAuth2IdentityRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class RevocationRequest extends OAuth2IdentityRequest {

    private static final long serialVersionUID = -371925192220383152L;

    private String token;
    private String tokenTypeHint;
    private String callback;

    protected RevocationRequest(RevokeRequestBuilder builder) {
        super(builder);
        this.token = builder.token;
        this.tokenTypeHint = builder.tokenTypeHint;
        this.callback = builder.callback;
    }

    public String getToken() {
        return token;
    }

    public String getTokenTypeHint() {
        return tokenTypeHint;
    }

    public String getCallback() {
        return callback;
    }

    public static class RevokeRequestBuilder extends OAuth2IdentityRequestBuilder {

        private String token;
        private String tokenTypeHint;
        private String callback;

        public RevokeRequestBuilder(HttpServletRequest request, HttpServletResponse response) {
            super(request, response);
        }

        public RevokeRequestBuilder() {

        }

        public RevokeRequestBuilder setToken(String token) {
            this.token = token;
            return this;
        }

        public RevokeRequestBuilder setTokenTypeHint(String tokenTypeHint) {
            this.tokenTypeHint = tokenTypeHint;
            return this;
        }

        public RevokeRequestBuilder setCallback(String callback) {
            this.callback = callback;
            return this;
        }

        @Override
        public RevocationRequest build() {
            return new RevocationRequest(this);
        }
    }
}
