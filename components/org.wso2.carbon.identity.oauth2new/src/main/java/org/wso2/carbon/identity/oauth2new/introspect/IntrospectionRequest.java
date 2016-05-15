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

import org.wso2.carbon.identity.oauth2new.bean.message.request.OAuth2IdentityRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class IntrospectionRequest extends OAuth2IdentityRequest {

    private static final long serialVersionUID = -371925192220383152L;

    private String token;
    private String tokenTypeHint;

    protected IntrospectionRequest(IntrospectionRequestBuilder builder) {
        super(builder);
        this.token = builder.token;
        this.tokenTypeHint = builder.tokenTypeHint;
    }

    public String getToken() {
        return token;
    }

    public String getTokenTypeHint() {
        return tokenTypeHint;
    }

    public static class IntrospectionRequestBuilder extends OAuth2IdentityRequestBuilder {

        private String token;
        private String tokenTypeHint;

        public IntrospectionRequestBuilder(HttpServletRequest request, HttpServletResponse response) {
            super(request, response);
        }

        public IntrospectionRequestBuilder() {
        }

        public IntrospectionRequestBuilder setToken(String token) {
            this.token = token;
            return this;
        }

        public IntrospectionRequestBuilder setTokenTypeHint(String tokenTypeHint) {
            this.tokenTypeHint = tokenTypeHint;
            return this;
        }

        @Override
        public IntrospectionRequest build() {
            return new IntrospectionRequest(this);
        }
    }
}
