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
import org.wso2.carbon.identity.oauth2new.OAuth2;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2TokenMessageContext;
import org.wso2.carbon.identity.oauth2new.cache.AccessTokenCache;
import org.wso2.carbon.identity.oauth2new.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth2new.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth2new.cache.AuthzCodeCache;
import org.wso2.carbon.identity.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.oauth2new.model.AuthzCode;
import org.wso2.carbon.identity.oauth2new.revoke.RevocationMessageContext;

import java.util.Set;

/*
 * Wraps a given OAuth2DAO object and provides caching feature for it
 */
public class CacheBackedOAuth2DAO extends OAuth2DAO {

    private OAuth2DAO wrappedDAO;

    public CacheBackedOAuth2DAO(OAuth2DAO dao) {
        this.wrappedDAO = dao;
    }

    @Override
    public AccessToken getLatestActiveOrExpiredAccessToken(String clientId, AuthenticatedUser authzUser, Set<String> scopes, OAuth2MessageContext messageContext) {

        AuthorizationGrantCacheKey key = new AuthorizationGrantCacheKey(clientId, authzUser, scopes);
        AccessToken accessToken = AuthorizationGrantCache.getInstance().getValueFromCache(key);
        if(accessToken != null) {
            return accessToken;
        }
        accessToken = wrappedDAO.getLatestActiveOrExpiredAccessToken(clientId, authzUser, scopes, messageContext);
        if(accessToken != null) {
            AuthorizationGrantCache.getInstance().addToCache(key, accessToken);
            if(AccessTokenCache.getInstance().getValueFromCache(accessToken.getAccessToken()) != null) {
                AccessTokenCache.getInstance().addToCache(accessToken.getAccessToken(), accessToken);
            }
        }
        return accessToken;
    }

    @Override
    public void storeAccessToken(AccessToken newAccessToken, String oldAccessToken, String authorizationCode,
                                 OAuth2MessageContext messageContext) {

        if(authorizationCode != null) {
            AuthzCode authzCode = AuthzCodeCache.getInstance().getValueFromCache(authorizationCode);
            if (authzCode != null) {
                AuthzCode newAuthzCode = AuthzCode.createAuthzCode(authzCode, OAuth2.TokenState.INACTIVE);
                AuthzCodeCache.getInstance().addToCache(authorizationCode, newAuthzCode);
            }
        }
        if(oldAccessToken != null){
            AccessToken accessToken = AccessTokenCache.getInstance().getValueFromCache(oldAccessToken);
            if(accessToken != null){
                AccessToken accessToken1 = AccessToken.createAccessToken(accessToken, OAuth2.TokenState.EXPIRED);
                AccessTokenCache.getInstance().addToCache(oldAccessToken, accessToken1);
            }
        }
        AuthorizationGrantCacheKey key = new AuthorizationGrantCacheKey(newAccessToken.getClientId(),
                newAccessToken.getAuthzUser(), newAccessToken.getScopes());
        AccessToken accessToken = AuthorizationGrantCache.getInstance().getValueFromCache(key);
        if(accessToken != null) {
            AuthorizationGrantCache.getInstance().addToCache(key, AccessToken.createAccessToken(accessToken,
                    OAuth2.TokenState.EXPIRED));
        }
        wrappedDAO.storeAccessToken(newAccessToken, oldAccessToken, authorizationCode, messageContext);
        AuthorizationGrantCache.getInstance().addToCache(key, newAccessToken);
        AccessTokenCache.getInstance().addToCache(newAccessToken.getAccessToken(), newAccessToken);

    }

    public void updateAccessTokenState(String bearerToken, String tokenState, OAuth2TokenMessageContext messageContext) {

        AccessToken accessToken = AccessTokenCache.getInstance().getValueFromCache(bearerToken);
        if(accessToken != null){
            AccessToken accessToken1 = AccessToken.createAccessToken(accessToken, tokenState);
            AccessTokenCache.getInstance().addToCache(bearerToken, accessToken1);
        }
        AuthorizationGrantCacheKey key = new AuthorizationGrantCacheKey(messageContext.getClientId(),
                messageContext.getAuthzUser(), messageContext.getApprovedScopes());
        accessToken = AuthorizationGrantCache.getInstance().getValueFromCache(key);
        if(accessToken != null) {
            AuthorizationGrantCache.getInstance().addToCache(key, AccessToken.createAccessToken(accessToken,
                    tokenState));
        }
        wrappedDAO.updateAccessTokenState(bearerToken, tokenState, messageContext);
    }

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
        AuthzCodeCache.getInstance().addToCache(authzCode.getAuthzCode(), authzCode);
    }

    @Override
    public AuthzCode getAuthzCode(String authorizationCode, OAuth2MessageContext messageContext) {

        AuthzCode authzCode = AuthzCodeCache.getInstance().getValueFromCache(authorizationCode);
        if(authzCode != null){
            return authzCode;
        }
        return wrappedDAO.getAuthzCode(authorizationCode, messageContext);
    }

    @Override
    public void updateAuthzCodeState(String authorizationCode, String state, OAuth2MessageContext messageContext) {

        AuthzCode authzCode = AuthzCodeCache.getInstance().getValueFromCache(authorizationCode);
        if(authzCode != null) {
            AuthzCodeCache.getInstance().addToCache(authorizationCode, AuthzCode.createAuthzCode(authzCode, state));
        }
        wrappedDAO.updateAuthzCodeState(authorizationCode, state, messageContext);
    }

    @Override
    public Set<String> getAuthorizedClientIDs(AuthenticatedUser authzUser, RevocationMessageContext messageContext) {
        return wrappedDAO.getAuthorizedClientIDs(authzUser, messageContext);
    }

    public AccessToken getAccessToken(String bearerToken, OAuth2MessageContext messageContext) {

        AccessToken accessToken = AccessTokenCache.getInstance().getValueFromCache(bearerToken);
        if(accessToken == null){
            accessToken = wrappedDAO.getAccessToken(bearerToken, messageContext);
            if(accessToken != null) {
                AccessTokenCache.getInstance().addToCache(bearerToken, accessToken);
                AuthorizationGrantCacheKey key = new AuthorizationGrantCacheKey(accessToken.getClientId(),
                        accessToken.getAuthzUser(), accessToken.getScopes());
                accessToken = AuthorizationGrantCache.getInstance().getValueFromCache(key);
                if(accessToken == null){
                    AuthorizationGrantCache.getInstance().addToCache(key, accessToken);
                }
            }
        }
        return accessToken;
    }

    @Override
    public void revokeAccessToken(String bearerToken, RevocationMessageContext messageContext) {

        AccessToken accessToken = null;
        accessToken = getAccessToken(bearerToken, messageContext);
        if(accessToken != null){
            AccessToken accessToken1 = AccessToken.createAccessToken(accessToken, OAuth2.TokenState.REVOKED);
            AccessTokenCache.getInstance().addToCache(bearerToken, accessToken1);
            String clientId = accessToken.getClientId();
            AuthenticatedUser user = accessToken.getAuthzUser();
            Set<String> scopes = accessToken.getScopes();
            AuthorizationGrantCacheKey key = new AuthorizationGrantCacheKey(clientId, user, scopes);
            accessToken = AuthorizationGrantCache.getInstance().getValueFromCache(key);
            if(accessToken != null) {
                AuthorizationGrantCache.getInstance().addToCache(key, accessToken1);
            }
            wrappedDAO.revokeAccessToken(bearerToken, messageContext);
        }
    }

    @Override
    public void revokeRefreshToken(String refreshToken, RevocationMessageContext messageContext) {

        AccessToken accessToken = null;
        accessToken = getLatestAccessTokenByRefreshToken(refreshToken, messageContext);
        if(accessToken != null){
            AccessToken accessToken1 = AccessToken.createAccessToken(accessToken, OAuth2.TokenState.REVOKED);
            AccessTokenCache.getInstance().addToCache(accessToken1.getAccessToken(), accessToken1);
            String clientId = accessToken.getClientId();
            AuthenticatedUser user = accessToken.getAuthzUser();
            Set<String> scopes = accessToken.getScopes();
            AuthorizationGrantCacheKey key = new AuthorizationGrantCacheKey(clientId, user, scopes);
            accessToken = AuthorizationGrantCache.getInstance().getValueFromCache(key);
            if(accessToken != null) {
                AuthorizationGrantCache.getInstance().addToCache(key, accessToken1);
            }
            wrappedDAO.revokeRefreshToken(refreshToken, messageContext);
        }
    }
}
