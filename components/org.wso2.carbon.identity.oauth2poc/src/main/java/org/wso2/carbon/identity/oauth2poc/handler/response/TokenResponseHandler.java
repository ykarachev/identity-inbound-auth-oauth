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

package org.wso2.carbon.identity.oauth2poc.handler.response;

import org.apache.commons.lang3.StringUtils;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.wso2.carbon.identity.application.authentication.framework.FrameworkHandlerResponse;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.processor.handler.response.ResponseException;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.oauth2poc.bean.message.request.authz.OAuth2AuthzRequest;
import org.wso2.carbon.identity.oauth2poc.bean.message.response.authz.AuthzResponse;
import org.wso2.carbon.identity.oauth2poc.handler.HandlerManager;
import org.wso2.carbon.identity.oauth2poc.model.AccessToken;
import org.wso2.carbon.identity.oauth2poc.util.OAuth2Util;

import javax.servlet.http.HttpServletResponse;

public class TokenResponseHandler extends OAuth2ResponseHandler {

    public String getName() {
        return "TokenResponseHandler";
    }

    public boolean canHandle(MessageContext messageContext) {
        AuthenticationContext authenticationContext = (AuthenticationContext)messageContext;
        String responseType = ((OAuth2AuthzRequest)authenticationContext.getInitialAuthenticationRequest())
                .getResponseType();
        if(StringUtils.equals(ResponseType.CODE.toString(), responseType)) {
            return true;
        }
        return false;
    }

    @Override
    public FrameworkHandlerResponse buildErrorResponse(IdentityMessageContext messageContext) throws ResponseException {
        return null;
    }

    @Override
    public FrameworkHandlerResponse buildResponse(IdentityMessageContext messageContext) throws ResponseException {
        AuthzResponse.AuthzResponseBuilder builder = buildAuthzResponse((AuthenticationContext)messageContext);
        FrameworkHandlerResponse response = FrameworkHandlerResponse.REDIRECT;
        response.setIdentityResponseBuilder(builder);
        return response;
    }

    /**
     * Issues the authorization endpoint response
     *
     * @param messageContext The runtime message context
     * @return OAuth2 authorization endpoint response
     */
    protected AuthzResponse.AuthzResponseBuilder buildAuthzResponse(AuthenticationContext messageContext) {

        AccessToken accessToken = HandlerManager.getInstance().issueAccessToken(messageContext);

        long expiry = 0;
        if(accessToken.getAccessTokenValidity() > 0) {
            expiry = accessToken.getAccessTokenValidity()/1000;
        } else {
            expiry = Long.MAX_VALUE/1000;
        }

        String state = messageContext.getInitialAuthenticationRequest().getParameter("state");

        // read redirect_uri from application.mgt
        String redirectURI = null;

        OAuthASResponse.OAuthAuthorizationResponseBuilder oltuRespBuilder = OAuthASResponse
                .authorizationResponse(null, HttpServletResponse.SC_FOUND)
                .location(redirectURI)
                .setAccessToken(accessToken.getAccessToken())
                .setExpiresIn(Long.toString(expiry))
                .setParam(OAuth.OAUTH_TOKEN_TYPE, OAuth.OAUTH_HEADER_NAME)
                .setParam(OAuth.OAUTH_STATE, state)
                .setParam(OAuth.OAUTH_SCOPE, OAuth2Util.buildScopeString(accessToken.getScopes()));


        if(issueRefreshToken(messageContext)) {
            oltuRespBuilder.setParam(OAuth.OAUTH_REFRESH_TOKEN, new String(accessToken.getRefreshToken()));
        }

        AuthzResponse.AuthzResponseBuilder builder = new AuthzResponse.AuthzResponseBuilder(messageContext);
        builder.setOLTUAuthzResponseBuilder(oltuRespBuilder);
        return builder;
    }
}
