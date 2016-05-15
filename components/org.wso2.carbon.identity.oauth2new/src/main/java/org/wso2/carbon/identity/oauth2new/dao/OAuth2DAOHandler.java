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

package org.wso2.carbon.identity.oauth2new.dao;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.core.handler.IdentityHandler;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2TokenMessageContext;
import org.wso2.carbon.identity.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.oauth2new.model.AuthzCode;
import org.wso2.carbon.identity.oauth2new.revoke.RevocationMessageContext;

import java.util.Set;

/*
 * For plugging in multiple OAuth2DAOs in runtime
 */
public final class OAuth2DAOHandler extends OAuth2DAO implements IdentityHandler {

    private OAuth2DAO wrappedDAO = null;

    private IdentityHandler identityHandler = new AbstractIdentityHandler() {
        @Override
        public String getName() {
            return "DefaultOAuth2DAOHandler";
        }
    };

    /*
     * Will use DefaultOAuth2DAOHandler
     */
    public OAuth2DAOHandler(OAuth2DAO oauth2DAO) {
        if(oauth2DAO == null){
            throw new IllegalArgumentException("OAuth2DAO is NULL");
        }
        this.wrappedDAO = oauth2DAO;
    }

    /*
     * Will use OAuth2DAOHandler that was passed in
     */
    public OAuth2DAOHandler(OAuth2DAO oauth2DAO, IdentityHandler identityHandler) {
        if(oauth2DAO == null){
            throw new IllegalArgumentException("OAuth2DAO is NULL");
        } else if (identityHandler == null) {
            throw new IllegalArgumentException("IdentityHandler is NULL");
        }
        this.wrappedDAO = oauth2DAO;
        this.identityHandler = identityHandler;
    }

    @Override
    public void init(InitConfig initConfig) {
        identityHandler.init(initConfig);
    }

    @Override
    public String getName() {
        return identityHandler.getName();
    }

    @Override
    public boolean isEnabled(MessageContext messageContext) {
        return identityHandler.isEnabled(messageContext);
    }

    @Override
    public int getPriority(MessageContext messageContext) {
        return identityHandler.getPriority(messageContext);
    }

    @Override
    public boolean canHandle(MessageContext messageContext) {
        return identityHandler.canHandle(messageContext);
    }

    @Override
    public AccessToken getLatestActiveOrExpiredAccessToken(String consumerKey, AuthenticatedUser authzUser,
                                                           Set<String> scopes, OAuth2MessageContext messageContext) {
        return wrappedDAO.getLatestActiveOrExpiredAccessToken(consumerKey, authzUser, scopes, messageContext);
    }

    @Override
    public void storeAccessToken(AccessToken newAccessToken, String oldAccessToken, String authzCode,
                                 OAuth2MessageContext messageContext) {
        wrappedDAO.storeAccessToken(newAccessToken, oldAccessToken, authzCode, messageContext);
    }

    public void updateAccessTokenState(String accessToken, String tokenState,
                                                OAuth2TokenMessageContext messageContext) {
        wrappedDAO.updateAuthzCodeState(accessToken, tokenState, messageContext);
    }

    @Override
    public String getAccessTokenByAuthzCode(String authorizationCode, OAuth2MessageContext messageContext) {
        return wrappedDAO.getAccessTokenByAuthzCode(authorizationCode, messageContext);
    }

    @Override
    public AccessToken getLatestAccessTokenByRefreshToken(String refreshToken, OAuth2MessageContext messageContext) {
        return wrappedDAO.getLatestAccessTokenByRefreshToken(refreshToken, messageContext);
    }

    @Override
    public void storeAuthzCode(AuthzCode authzCode, OAuth2MessageContext messageContext) {
        wrappedDAO.storeAuthzCode(authzCode, messageContext);
    }

    @Override
    public AuthzCode getAuthzCode(String authzCode, OAuth2MessageContext messageContext) {
        return wrappedDAO.getAuthzCode(authzCode, messageContext);
    }

    @Override
    public void updateAuthzCodeState(String authzCode, String state, OAuth2MessageContext messageContext) {
        wrappedDAO.updateAuthzCodeState(authzCode, state, messageContext);
    }

    @Override
    public Set<String> getAuthorizedClientIDs(AuthenticatedUser authzUser, RevocationMessageContext messageContext) {
        return wrappedDAO.getAuthorizedClientIDs(authzUser, messageContext);
    }

    @Override
    public AccessToken getAccessToken(String bearerToken, OAuth2MessageContext messageContext) {
        return wrappedDAO.getAccessToken(bearerToken, messageContext);
    }

    @Override
    public void revokeAccessToken(String accessToken, RevocationMessageContext messageContext) {
        wrappedDAO.revokeAccessToken(accessToken, messageContext);
    }

    @Override
    public void revokeRefreshToken(String refreshToken, RevocationMessageContext messageContext) {
        wrappedDAO.revokeRefreshToken(refreshToken, messageContext);
    }
}
