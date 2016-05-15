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

package org.wso2.carbon.identity.oauth2new.processor.token;


import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2TokenMessageContext;
import org.wso2.carbon.identity.oauth2new.bean.message.request.token.OAuth2TokenRequest;
import org.wso2.carbon.identity.oauth2new.bean.message.response.token.TokenResponse;
import org.wso2.carbon.identity.oauth2new.common.ClientType;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2ClientException;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.oauth2new.handler.HandlerManager;
import org.wso2.carbon.identity.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.oauth2new.processor.OAuth2IdentityRequestProcessor;
import org.wso2.carbon.identity.oauth2new.util.OAuth2Util;

import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;

/*
 * InboundRequestProcessor for OAuth2 Token Endpoint
 */
public class TokenProcessor extends OAuth2IdentityRequestProcessor {

    @Override
    public String getName() {
        return "TokenProcessor";
    }

    @Override
    public int getPriority() {
        return 0;
    }

    @Override
    public String getCallbackPath(IdentityMessageContext context) {
        return null;
    }

    @Override
    public String getRelyingPartyId() {
        return null;
    }

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        if(identityRequest.getParameter(OAuth.OAUTH_GRANT_TYPE) != null) {
            return true;
        }
        return false;
    }

    @Override
    public TokenResponse.TokenResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {

        OAuth2TokenMessageContext messageContext = new OAuth2TokenMessageContext(
                (OAuth2TokenRequest) identityRequest, new HashMap<String,String>());

        if(ClientType.CONFIDENTIAL == clientType(messageContext)) {
            String clientId = authenticateClient(messageContext);
            messageContext.setClientId(clientId);
        }

        validateGrant(messageContext);

        AccessToken accessToken = issueAccessToken(messageContext);

        return buildTokenResponse(accessToken, messageContext);

    }

    /**
     * Finds out the client type
     *
     * @param messageContext The runtime message context
     * @return {@code true} only if the client was confidential and was authenticated successfully
     * @throws OAuth2Exception
     */
    protected ClientType clientType(OAuth2TokenMessageContext messageContext) {
        return HandlerManager.getInstance().clientType(messageContext);
    }

    /**
     * Authenticates confidential clients
     *
     * @param messageContext The runtime message context
     * @return {@code true} only if the client was confidential and was authenticated successfully
     * @throws OAuth2Exception
     */
    protected String authenticateClient(OAuth2TokenMessageContext messageContext) throws OAuth2Exception {
        return HandlerManager.getInstance().authenticateClient(messageContext);
    }

    /**
     * Validates the Authorization Grant
     *
     * @param messageContext The runtime message context
     * @return {@code true} only if the authorization grant is valid
     * @throws OAuth2Exception
     */
    protected void validateGrant(OAuth2TokenMessageContext messageContext) throws OAuth2ClientException, OAuth2Exception {
        HandlerManager.getInstance().validateGrant(messageContext);
    }

    protected TokenResponse.TokenResponseBuilder buildTokenResponse(AccessToken accessToken,
                                                                        OAuth2TokenMessageContext messageContext) {

        long expiry = 0;
        if(accessToken.getAccessTokenValidity() > 0) {
            expiry = accessToken.getAccessTokenValidity()/1000;
        } else {
            expiry = Long.MAX_VALUE/1000;
        }

        // Have to check if refresh grant is allowed

        String refreshToken = null;
        if(issueRefreshToken(messageContext)) {
            refreshToken = accessToken.getRefreshToken();
        }

        OAuthASResponse.OAuthTokenResponseBuilder oltuRespBuilder = OAuthASResponse
                .tokenResponse(HttpServletResponse.SC_OK)
                .setAccessToken(accessToken.getAccessToken())
                .setRefreshToken(new String(refreshToken))
                .setExpiresIn(Long.toString(expiry))
                .setTokenType(OAuth.OAUTH_HEADER_NAME);
        oltuRespBuilder.setScope(OAuth2Util.buildScopeString(accessToken.getScopes()));

        TokenResponse.TokenResponseBuilder builder = new TokenResponse.TokenResponseBuilder(messageContext);
        builder.setBuilder(oltuRespBuilder);
        return builder;
    }

    /**
     * Issues the access token
     *
     * @param messageContext The runtime message context
     * @return OAuth2 access token response
     * @throws OAuth2Exception
     */
    protected AccessToken issueAccessToken(OAuth2TokenMessageContext messageContext) {
        return HandlerManager.getInstance().issueAccessToken(messageContext);
    }
}
