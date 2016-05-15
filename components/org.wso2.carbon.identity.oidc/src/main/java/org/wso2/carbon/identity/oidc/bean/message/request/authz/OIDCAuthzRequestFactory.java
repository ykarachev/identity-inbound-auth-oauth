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

package org.wso2.carbon.identity.oidc.bean.message.request.authz;

import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.oauth2new.bean.message.request.authz.AuthzRequestFactory;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2ClientException;
import org.wso2.carbon.identity.oauth2new.util.OAuth2Util;
import org.wso2.carbon.identity.oidc.OIDC;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Set;

public class OIDCAuthzRequestFactory extends AuthzRequestFactory {

    @Override
    public String getName() {
        return "OIDCAuthzRequestFactory";
    }

    @Override
    public int getPriority() {
        return 0;
    }

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) {
        if(super.canHandle(request, response)) {
            Set<String> scopes = OAuth2Util.buildScopeSet(request.getParameter(OAuth.OAUTH_SCOPE));
            if (scopes.contains(OIDC.OPENID_SCOPE)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public OIDCAuthzRequest.OIDCAuthzRequestBuilder create(HttpServletRequest request,
                                                           HttpServletResponse response) throws OAuth2ClientException {

        OIDCAuthzRequest.OIDCAuthzRequestBuilder builder = new OIDCAuthzRequest.OIDCAuthzRequestBuilder
                (request, response);
        builder.setTenantDomain(request.getParameter(MultitenantConstants.TENANT_DOMAIN));
        builder.setResponseType(request.getParameter(OAuth.OAUTH_RESPONSE_TYPE));
        builder.setClientId(request.getParameter(OAuth.OAUTH_CLIENT_ID));
        builder.setRedirectURI(request.getParameter(OAuth.OAUTH_REDIRECT_URI));
        builder.setState(request.getParameter(OAuth.OAUTH_STATE));
        builder.setScopes(OAuth2Util.buildScopeSet(request.getParameter(OAuth.OAUTH_SCOPE)));
        builder.setNonce(request.getParameter(OIDC.NONCE));
        builder.setDisplay(request.getParameter(OIDC.DISPLAY));
        builder.setIdTokenHint(request.getParameter(OIDC.ID_TOKEN_HINT));
        builder.setLoginHint(request.getParameter(OIDC.LOGIN_HINT));
        Set<String> prompts = OAuth2Util.buildScopeSet(request.getParameter(OIDC.PROMPT));
        if(prompts.contains(OIDC.Prompt.NONE) && prompts.size() > 1){
            throw OAuth2ClientException.error("Prompt value 'none' cannot be used with other " +
            "prompts. Prompt: " + request.getParameter(OIDC.PROMPT));
        }
        builder.setPrompts(prompts);
        if (prompts.contains(OIDC.Prompt.LOGIN)) {
            builder.setLoginRequired(true);
        }
        if(prompts.contains(OIDC.Prompt.CONSENT)) {
            builder.setConsentRequired(true);
        }
        return builder;
    }
}
