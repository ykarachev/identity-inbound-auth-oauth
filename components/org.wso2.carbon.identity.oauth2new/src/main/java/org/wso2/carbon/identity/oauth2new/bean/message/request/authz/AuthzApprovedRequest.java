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

package org.wso2.carbon.identity.oauth2new.bean.message.request.authz;

import org.wso2.carbon.identity.oauth2new.bean.message.request.OAuth2IdentityRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AuthzApprovedRequest extends OAuth2IdentityRequest {

    private static final long serialVersionUID = 3359421085612381634L;

    private String sessionDataKey;
    private String consent;

    protected AuthzApprovedRequest(AuthzApprovedRequestBuilder builder) {
        super(builder);
        this.sessionDataKey = builder.sessionDataKey;
        this.consent = builder.consent;
    }

    public String getSessionDataKey() {
        return this.sessionDataKey;
    }

    public String getConsent() {
        return this.consent;
    }

    public static class AuthzApprovedRequestBuilder extends OAuth2IdentityRequestBuilder {

        private String sessionDataKey;
        private String consent;

        public AuthzApprovedRequestBuilder(HttpServletRequest request, HttpServletResponse response) {
            super(request, response);
        }

        public AuthzApprovedRequestBuilder() {

        }

        public AuthzApprovedRequestBuilder setSessionDataKey(String sessionDataKey) {
            this.sessionDataKey = sessionDataKey;
            return this;
        }

        public AuthzApprovedRequestBuilder setConsent(String consent) {
            this.consent = consent;
            return this;
        }

        @Override
        public AuthzApprovedRequest build() {
            return new AuthzApprovedRequest(this);
        }
    }
}
