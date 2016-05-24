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
import org.wso2.carbon.identity.application.authentication.framework.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.IdentityRequest;
import org.wso2.carbon.identity.oauth2poc.bean.message.request.authz.AuthzRequestFactory;
import org.wso2.carbon.identity.oauth2poc.exception.OAuth2ClientException;
import org.wso2.carbon.identity.oauth2poc.util.OAuth2Util;
import org.wso2.carbon.identity.oidc.OIDC;

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
        try {
            super.create(builder, request, response);
        } catch (FrameworkClientException e) {
            throw OAuth2ClientException.error(e.getMessage(), e);
        }
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

    @Override
    public OIDCAuthzRequest.OIDCAuthzRequestBuilder create(IdentityRequest.IdentityRequestBuilder builder,
                                                           HttpServletRequest request,
                                                           HttpServletResponse response) throws OAuth2ClientException {

        OIDCAuthzRequest.OIDCAuthzRequestBuilder oidcAuthzRequestBuilder =
                (OIDCAuthzRequest.OIDCAuthzRequestBuilder)builder;
        try {
            super.create(oidcAuthzRequestBuilder, request, response);
        } catch (FrameworkClientException e) {
            throw OAuth2ClientException.error(e.getMessage(), e);
        }
        oidcAuthzRequestBuilder.setNonce(request.getParameter(OIDC.NONCE));
        oidcAuthzRequestBuilder.setDisplay(request.getParameter(OIDC.DISPLAY));
        oidcAuthzRequestBuilder.setIdTokenHint(request.getParameter(OIDC.ID_TOKEN_HINT));
        oidcAuthzRequestBuilder.setLoginHint(request.getParameter(OIDC.LOGIN_HINT));
        Set<String> prompts = OAuth2Util.buildScopeSet(request.getParameter(OIDC.PROMPT));
        if(prompts.contains(OIDC.Prompt.NONE) && prompts.size() > 1){
            throw OAuth2ClientException.error("Prompt value 'none' cannot be used with other " +
                                              "prompts. Prompt: " + request.getParameter(OIDC.PROMPT));
        }
        oidcAuthzRequestBuilder.setPrompts(prompts);
        if (prompts.contains(OIDC.Prompt.LOGIN)) {
            oidcAuthzRequestBuilder.setLoginRequired(true);
        }
        if(prompts.contains(OIDC.Prompt.CONSENT)) {
            oidcAuthzRequestBuilder.setConsentRequired(true);
        }
        return oidcAuthzRequestBuilder;
    }
}
