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

package org.wso2.carbon.identity.oauth2new.bean.message.response.token;

import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;

public class TokenResponse extends IdentityResponse {

    private OAuthASResponse.OAuthTokenResponseBuilder builder;

    public OAuthASResponse.OAuthTokenResponseBuilder getBuilder() {
        return builder;
    }

    protected TokenResponse(IdentityResponseBuilder builder) {
        super(builder);
        this.builder = ((TokenResponseBuilder)builder).builder;
    }

    public static class TokenResponseBuilder extends IdentityResponseBuilder {

        private OAuthASResponse.OAuthTokenResponseBuilder builder;

        public TokenResponseBuilder(IdentityMessageContext context) {
            super(context);
        }

        public OAuthASResponse.OAuthTokenResponseBuilder getBuilder() {
            return builder;
        }

        public TokenResponseBuilder setBuilder(OAuthASResponse.OAuthTokenResponseBuilder builder) {
            this.builder = builder;
            return this;
        }

        public TokenResponse build() {
            return new TokenResponse(this);
        }
    }
}
