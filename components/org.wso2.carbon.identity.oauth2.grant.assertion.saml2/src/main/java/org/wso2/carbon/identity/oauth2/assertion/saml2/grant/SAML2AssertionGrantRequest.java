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

package org.wso2.carbon.identity.oauth2.assertion.saml2.grant;

import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkRuntimeException;
import org.wso2.carbon.identity.oauth2new.bean.message.request.token.OAuth2TokenRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashSet;
import java.util.Set;

public class SAML2AssertionGrantRequest extends OAuth2TokenRequest {

    private static final long serialVersionUID = -4072916934667966426L;

    private String assertion;
    private String assertionType;
    private Set<String> scopes = new HashSet<>();

    protected SAML2AssertionGrantRequest(SAML2AssertionGrantBuilder builder) {
        super(builder);
        this.assertion = builder.assertion;
        this.assertionType = builder.assertionType;
        this.scopes = builder.scopes;
    }

    public String getAssertion() {
        return assertion;
    }

    public String getAssertionType() {
        return assertionType;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public static class SAML2AssertionGrantBuilder extends TokenRequestBuilder {

        private String assertion;
        private String assertionType;
        private Set<String> scopes;

        public SAML2AssertionGrantBuilder(HttpServletRequest request, HttpServletResponse response) {
            super(request, response);
        }

        public SAML2AssertionGrantBuilder setAssertion(String assertion) {
            this.assertion = assertion;
            return this;
        }

        public SAML2AssertionGrantBuilder setAssertionType(String assertionType) {
            this.assertionType = assertionType;
            return this;
        }

        public SAML2AssertionGrantBuilder setScopes(Set<String> scopes) {
            this.scopes = scopes;
            return this;
        }

        @Override
        public SAML2AssertionGrantRequest build() throws FrameworkRuntimeException {
            return new SAML2AssertionGrantRequest(this);
        }
    }
}
