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

package org.wso2.carbon.identity.oauth2new.revoke;

import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.oauth2new.common.ClientType;
import org.wso2.carbon.identity.oauth2new.dao.OAuth2DAO;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.oauth2new.handler.HandlerManager;
import org.wso2.carbon.identity.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.oauth2new.processor.OAuth2IdentityRequestProcessor;

import java.util.HashMap;

public class RevocationProcessor extends OAuth2IdentityRequestProcessor {

    @Override
    public String getName() {
        return "RevocationProcessor";
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
    public int getPriority() {
        return 0;
    }

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        if(StringUtils.isNotBlank(identityRequest.getParameter("token"))) {
            return true;
        }
        return false;
    }

    @Override
    public RevocationResponse.RevocationResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {

        RevocationRequest revocationRequest = (RevocationRequest) identityRequest;
        RevocationMessageContext messageContext = new RevocationMessageContext(revocationRequest,
                new HashMap<String,String>());

        if(ClientType.CONFIDENTIAL == clientType(messageContext)) {
            String clientId = authenticateClient(messageContext);
            messageContext.setClientId(clientId);
        }

        String token = revocationRequest.getToken();
        String tokenTypeHint = revocationRequest.getTokenTypeHint();
        OAuth2DAO dao = HandlerManager.getInstance().getOAuth2DAO(messageContext);
        boolean refreshTokenFirst = GrantType.REFRESH_TOKEN.toString().equals(tokenTypeHint) ? true : false;
        AccessToken accessToken = null;
        if (refreshTokenFirst) {
            accessToken = dao.getLatestAccessTokenByRefreshToken(token, messageContext);
            if(accessToken != null) {
                dao.revokeRefreshToken(token, messageContext);
                messageContext.addParameter("RevokedAccessToken", accessToken);
            } else {
                accessToken = dao.getAccessToken(token, messageContext);
                if(accessToken != null) {
                    dao.revokeAccessToken(accessToken.getAccessToken(), messageContext);
                    messageContext.addParameter("RevokedAccessToken", accessToken);
                }
            }
        } else {
            accessToken = dao.getAccessToken(token, messageContext);
            if (accessToken != null) {
                dao.revokeAccessToken(token, messageContext);
                messageContext.addParameter("RevokedAccessToken", accessToken);
            } else {
                accessToken = dao.getLatestAccessTokenByRefreshToken(token, messageContext);
                if(accessToken != null) {
                    dao.revokeRefreshToken(token, messageContext);
                    messageContext.addParameter("RevokedAccessToken", accessToken);
                }
            }
        }

        RevocationResponse.RevocationResponseBuilder responseBuilder = new RevocationResponse
                .RevocationResponseBuilder(messageContext);
        responseBuilder.setCallback(revocationRequest.getCallback());
        return responseBuilder;
    }

    /**
     * Finds out the client type
     *
     * @param messageContext The runtime message context
     * @return {@code true} only if the client was confidential and was authenticated successfully
     * @throws org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception
     */
    protected ClientType clientType(RevocationMessageContext messageContext) {
        return HandlerManager.getInstance().clientType(messageContext);
    }

    /**
     * Authenticates confidential clients
     *
     * @param messageContext The runtime message context
     * @return {@code true} only if the client was confidential and was authenticated successfully
     * @throws org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception
     */
    protected String authenticateClient(RevocationMessageContext messageContext) throws OAuth2Exception {
        return HandlerManager.getInstance().authenticateClient(messageContext);
    }
}
