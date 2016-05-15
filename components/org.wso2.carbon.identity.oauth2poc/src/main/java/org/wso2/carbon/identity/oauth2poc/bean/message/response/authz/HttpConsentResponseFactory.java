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

package org.wso2.carbon.identity.oauth2poc.bean.message.response.authz;

import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2poc.OAuth2;
import org.wso2.carbon.identity.oauth2poc.exception.OAuth2RuntimeException;
import org.wso2.carbon.identity.oauth2poc.model.OAuth2ServerConfig;
import org.wso2.carbon.identity.oauth2poc.util.OAuth2Util;

import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

public class HttpConsentResponseFactory extends HttpIdentityResponseFactory {

    @Override
    public String getName() {
        return "HttpConsentResponseFactory";
    }

    @Override
    public boolean canHandle(IdentityResponse identityResponse) {
        if(identityResponse instanceof ConsentResponse) {
            return true;
        }
        return false;
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder create(IdentityResponse identityResponse) {

        ConsentResponse consentResponse = (ConsentResponse)identityResponse;

        String consentPageURL = OAuth2ServerConfig.getInstance().getConsentPageURL();
        String queryString = null;
        try {
            queryString = IdentityUtil.buildQueryString(consentResponse.getParameterMap());
        } catch (UnsupportedEncodingException e) {
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        }
        String applicationName = consentResponse.getApplicationName();
        String authenticatedSubjectId = consentResponse.getAuthenticatedSubjectId();
        String requestedScopes =  OAuth2Util.buildScopeString(consentResponse.getRequestedScopes());
        String sessionDataKeyConsent = consentResponse.getSessionDataKeyConsent();
        try {
            consentPageURL += queryString + OAuth2.LOGGED_IN_USER + "=" +
                           URLEncoder.encode(authenticatedSubjectId, "UTF-8") +
                           "&application=" + URLEncoder.encode(applicationName, "ISO-8859-1") +
                           "&" + OAuth.OAUTH_SCOPE + "=" + URLEncoder.encode(requestedScopes, "ISO-8859-1") +
                           "&" + OAuth2.SESSION_DATA_KEY_CONSENT + "=" + URLEncoder
                                   .encode(sessionDataKeyConsent, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        }

        HttpIdentityResponse.HttpIdentityResponseBuilder builder = new HttpIdentityResponse
                .HttpIdentityResponseBuilder();
        builder.setStatusCode(HttpServletResponse.SC_FOUND);
        builder.setRedirectURL(consentPageURL);
        return builder;
    }
}
