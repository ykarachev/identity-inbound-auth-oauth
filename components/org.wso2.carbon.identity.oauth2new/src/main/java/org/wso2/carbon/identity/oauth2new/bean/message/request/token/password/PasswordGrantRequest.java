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

package org.wso2.carbon.identity.oauth2new.bean.message.request.token.password;

import org.wso2.carbon.identity.oauth2new.bean.message.request.token.OAuth2TokenRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashSet;
import java.util.Set;

public class PasswordGrantRequest extends OAuth2TokenRequest {

    private static final long serialVersionUID = -4072916934667966426L;

    private String username;
    private char[] password;
    private Set<String> scopes = new HashSet<>();

    protected PasswordGrantRequest(PasswordGrantBuilder builder) {
        super(builder);
        this.username = builder.username;
        this.password = builder.password;
        this.scopes = builder.scopes;
    }

    public String getUsername() {
        return username;
    }

    public char[] getPassword() {
        return password;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public static class PasswordGrantBuilder extends TokenRequestBuilder {

        private String username;
        private char[] password;
        private Set<String> scopes;

        public PasswordGrantBuilder(HttpServletRequest request, HttpServletResponse response) {
            super(request, response);
        }

        public PasswordGrantBuilder() {
        }

        public PasswordGrantBuilder setUsername(String username) {
            this.username = username;
            return this;
        }

        public PasswordGrantBuilder setPassword(char[] password) {
            this.password = password;
            return this;
        }

        public PasswordGrantBuilder setScopes(Set<String> scopes) {
            this.scopes = scopes;
            return this;
        }

        @Override
        public PasswordGrantRequest build() {
            return new PasswordGrantRequest(this);
        }
    }
}
