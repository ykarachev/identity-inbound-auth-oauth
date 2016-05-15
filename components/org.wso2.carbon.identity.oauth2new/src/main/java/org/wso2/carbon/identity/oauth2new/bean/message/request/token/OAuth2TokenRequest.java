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

package org.wso2.carbon.identity.oauth2new.bean.message.request.token;

import org.wso2.carbon.identity.oauth2new.bean.message.request.OAuth2IdentityRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class OAuth2TokenRequest extends OAuth2IdentityRequest {

    private static final long serialVersionUID = -4100425188456499228L;

    private String grantType;

    protected OAuth2TokenRequest(TokenRequestBuilder builder) {
        super(builder);
        this.grantType = builder.grantType;
    }

    public String getGrantType() {
        return grantType;
    }

    public static class TokenRequestBuilder extends OAuth2IdentityRequestBuilder {

        private String grantType;

        public TokenRequestBuilder(HttpServletRequest request, HttpServletResponse response) {
            super(request, response);
        }

        public TokenRequestBuilder() {

        }

        public TokenRequestBuilder setGrantType(String grantType) {
            this.grantType = grantType;
            return this;
        }

        public OAuth2TokenRequest build() {

            return new OAuth2TokenRequest(this);
        }

    }
}
