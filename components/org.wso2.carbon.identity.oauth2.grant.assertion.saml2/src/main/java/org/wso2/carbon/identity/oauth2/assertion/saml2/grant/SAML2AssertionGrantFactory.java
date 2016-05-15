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

import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.oauth2new.bean.message.request.token.TokenRequestFactory;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2ClientException;
import org.wso2.carbon.identity.oauth2new.util.OAuth2Util;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SAML2AssertionGrantFactory extends TokenRequestFactory {

    @Override
    public String getName() {
        return "SAML2AssertionGrantFactory";
    }

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) {
        if(StringUtils.equals(SAML2GrantConstants.SAML2_GRANT_TYPE, request.getParameter(OAuth.OAUTH_GRANT_TYPE))) {
            return true;
        }
        return false;
    }

    @Override
    public SAML2AssertionGrantRequest.SAML2AssertionGrantBuilder create(HttpServletRequest request,
                                                                        HttpServletResponse response)
            throws OAuth2ClientException {

        SAML2AssertionGrantRequest.SAML2AssertionGrantBuilder builder = new SAML2AssertionGrantRequest.SAML2AssertionGrantBuilder
                (request, response);
        builder.setAssertion(request.getParameter(OAuth.OAUTH_ASSERTION));
        builder.setAssertionType(request.getParameter(OAuth.OAUTH_ASSERTION_TYPE));
        builder.setScopes(OAuth2Util.buildScopeSet(request.getParameter(OAuth.OAUTH_SCOPE)));
        return builder;
    }
}
