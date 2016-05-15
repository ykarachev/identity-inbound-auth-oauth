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

package org.wso2.carbon.identity.oidc.userinfo;

import org.wso2.carbon.identity.oauth2new.bean.message.request.OAuth2IdentityRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class UserInfoRequest extends OAuth2IdentityRequest {

    private static final long serialVersionUID = -3009563708954787261L;

    private String nonce;
    private String display;
    private String idTokenHint;
    private String loginHint;
    private String prompt;

    protected UserInfoRequest(UserInfoRequestBuilder builder) {
        super(builder);
        this.nonce = builder.nonce;
        this.display = builder.display;
        this.idTokenHint = builder.idTokenHint;
        this.loginHint = builder.loginHint;
        this.prompt = builder.prompt;
    }

    public String getNonce() {
        return nonce;
    }

    public String getDisplay() {
        return display;
    }

    public String getIdTokenHint() {
        return idTokenHint;
    }

    public String getLoginHint() {
        return loginHint;
    }

    public String getPrompt() {
        return prompt;
    }

    public static class UserInfoRequestBuilder extends OAuth2IdentityRequestBuilder {

        public UserInfoRequestBuilder(HttpServletRequest request, HttpServletResponse response) {
            super(request, response);
        }

        public UserInfoRequestBuilder() {

        }

        private String nonce;
        private String display;
        private String idTokenHint;
        private String loginHint;
        private String prompt;

        public UserInfoRequestBuilder setNonce(String nonce) {
            this.nonce = nonce;
            return this;
        }

        public UserInfoRequestBuilder setDisplay(String display) {
            this.display = display;
            return this;
        }

        public UserInfoRequestBuilder setIdTokenHint(String idTokenHint) {
            this.idTokenHint = idTokenHint;
            return this;
        }

        public UserInfoRequestBuilder setLoginHint(String loginHint) {
            this.loginHint = loginHint;
            return this;
        }

        public UserInfoRequestBuilder setPrompt(String prompt) {
            this.prompt = prompt;
            return this;
        }

        public UserInfoRequest build() {
            return new UserInfoRequest(this);
        }
    }
}
