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

package org.wso2.carbon.identity.oauth2new.handler.issuer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.oauth2new.OAuth2;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2AuthzMessageContext;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2TokenMessageContext;
import org.wso2.carbon.identity.oauth2new.dao.OAuth2DAO;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2RuntimeException;
import org.wso2.carbon.identity.oauth2new.handler.HandlerManager;
import org.wso2.carbon.identity.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.oauth2new.util.OAuth2Util;

import java.util.Set;

/*
 * To generate OAuth2 access tokens
 */
public abstract class AccessTokenResponseIssuer extends AbstractIdentityHandler {

    private static Log log = LogFactory.getLog(AccessTokenResponseIssuer.class);

    protected static final String IS_ACCESS_TOKEN_VALID = "IsAccessTokenValid";
    protected static final String IS_REFRESH_TOKEN_VALID = "IsRefreshTokenValid";
    protected static final String MARK_ACCESS_TOKEN_EXPIRED = "MarkAccessTokenExpired";

    /**
     * Issues the access token response.
     *
     * @param messageContext The runtime message context
     * @return Returns the OAuth2 response
     * @throws OAuth2Exception
     */
    public AccessToken issue(OAuth2MessageContext messageContext) {

        AccessToken accessToken = validTokenExists(messageContext);
        boolean isAccessTokenValid = (Boolean)messageContext.getParameter(IS_ACCESS_TOKEN_VALID);
        boolean isRefreshTokenValid = (Boolean)messageContext.getParameter(IS_REFRESH_TOKEN_VALID);
        if(!isAccessTokenValid || !isRefreshTokenValid) {
            accessToken = issueNewAccessToken(messageContext);
            storeNewAccessToken(accessToken, messageContext);
        }
        return accessToken;
    }

    protected AccessToken validTokenExists(OAuth2MessageContext messageContext) {

        if(messageContext instanceof OAuth2AuthzMessageContext) {
            return validTokenExists((OAuth2AuthzMessageContext)messageContext);
        } else if (messageContext instanceof OAuth2TokenMessageContext) {
            return validTokenExists((OAuth2TokenMessageContext)messageContext);
        } else {
            throw OAuth2RuntimeException.error("");
        }
    }

    protected AccessToken validTokenExists(OAuth2AuthzMessageContext messageContext) {

        String clientId = messageContext.getRequest().getClientId();
        AuthenticatedUser authzUser = messageContext.getAuthzUser();
        Set<String> scopes = messageContext.getApprovedScopes();
        return validTokenExists(clientId, authzUser, scopes, messageContext);
    }

    protected AccessToken validTokenExists(OAuth2TokenMessageContext messageContext) {

        String clientId = messageContext.getClientId();
        AuthenticatedUser authzUser = messageContext.getAuthzUser();
        Set<String> scopes = messageContext.getApprovedScopes();
        return validTokenExists(clientId, authzUser, scopes, messageContext);
    }

    protected AccessToken validTokenExists(String clientId, AuthenticatedUser authzUser,
                                           Set<String> scopes, OAuth2MessageContext messageContext) {

        OAuth2DAO dao = HandlerManager.getInstance().getOAuth2DAO(messageContext);
        AccessToken accessToken = dao.getLatestActiveOrExpiredAccessToken(clientId, authzUser, scopes, messageContext);
        boolean isAccessTokenValid = false;
        boolean isRefreshTokenValid = false;
        boolean markAccessTokenExpired = false;

        if (accessToken != null) {
            if (OAuth2.TokenState.ACTIVE.equals(accessToken.getAccessTokenState())) {
                long expireTime = OAuth2Util.getTokenValidityPeriod(accessToken);
                if (expireTime > 0 || expireTime < 0) {
                    if (log.isDebugEnabled()) {
                        if (expireTime > 0) {
                            log.debug("ACTIVE access token found for " + OAuth2Util.createUniqueAuthzGrantString
                                    (authzUser, clientId, scopes));
                        } else if (expireTime < 0) {
                            log.debug("Infinite lifetime access token found for " + OAuth2Util
                                    .createUniqueAuthzGrantString(authzUser, clientId, scopes));
                        }
                    }
                    isAccessTokenValid = true;
                    long refreshTokenExpiryTime = OAuth2Util.getRefreshTokenValidityPeriod(accessToken);
                    if (refreshTokenExpiryTime < 0 || refreshTokenExpiryTime > 0) {
                        if (log.isDebugEnabled()) {
                            if (refreshTokenExpiryTime < 0) {
                                log.debug("Infinite lifetime refresh token found for " + OAuth2Util
                                        .createUniqueAuthzGrantString(authzUser, clientId, scopes));
                            } else if (refreshTokenExpiryTime > 0) {
                                log.debug("ACTIVE refresh token found for " + OAuth2Util.createUniqueAuthzGrantString
                                        (authzUser, clientId, scopes));
                            }
                        }
                        isRefreshTokenValid = true;
                    }
                } else {
                    markAccessTokenExpired = true;
                }
            } else {
                long refreshTokenExpiryTime = OAuth2Util.getRefreshTokenValidityPeriod(accessToken);
                if (refreshTokenExpiryTime < 0 || refreshTokenExpiryTime > 0) {
                    if (log.isDebugEnabled()) {
                        if (refreshTokenExpiryTime < 0) {
                            log.debug("Infinite lifetime refresh token found for " + OAuth2Util
                                    .createUniqueAuthzGrantString(authzUser, clientId, scopes));
                        } else if (refreshTokenExpiryTime > 0) {
                            log.debug("ACTIVE refresh token found for " + OAuth2Util.createUniqueAuthzGrantString
                                    (authzUser, clientId, scopes));
                        }
                    }
                    isRefreshTokenValid = true;
                }
            }

        }
        messageContext.addParameter(IS_ACCESS_TOKEN_VALID, isAccessTokenValid);
        messageContext.addParameter(IS_REFRESH_TOKEN_VALID, isRefreshTokenValid);
        messageContext.addParameter(MARK_ACCESS_TOKEN_EXPIRED, markAccessTokenExpired);
        messageContext.addParameter(OAuth2.PREV_ACCESS_TOKEN, accessToken);
        return accessToken;
    }

    protected AccessToken issueNewAccessToken(OAuth2MessageContext messageContext) {

        if(messageContext instanceof OAuth2AuthzMessageContext) {
            return issueNewAccessToken((OAuth2AuthzMessageContext) messageContext);
        } else if (messageContext instanceof OAuth2TokenMessageContext) {
            return issueNewAccessToken((OAuth2TokenMessageContext) messageContext);
        } else {
            throw OAuth2RuntimeException.error("");
        }
    }

    protected AccessToken issueNewAccessToken(OAuth2AuthzMessageContext messageContext) {

        boolean isRefreshTokenValid = (Boolean)messageContext.getParameter(IS_REFRESH_TOKEN_VALID);
        boolean markAccessTokenExpired = (Boolean)messageContext.getParameter(MARK_ACCESS_TOKEN_EXPIRED);
        AccessToken prevAccessToken = (AccessToken)messageContext.getParameter(OAuth2.PREV_ACCESS_TOKEN);
        String clientId = messageContext.getRequest().getClientId();
        AuthenticatedUser authzUser = messageContext.getAuthzUser();
        Set<String> scopes = messageContext.getApprovedScopes();
        long accessTokenCallbackValidity = messageContext.getValidityPeriod();
        long refreshTokenCallbackValidity = messageContext.getValidityPeriod();
        String responseType = messageContext.getRequest().getResponseType();
        return issueNewAccessToken(clientId, authzUser, scopes, isRefreshTokenValid,
                markAccessTokenExpired, prevAccessToken, accessTokenCallbackValidity, refreshTokenCallbackValidity,
                responseType, messageContext);
    }

    protected AccessToken issueNewAccessToken(OAuth2TokenMessageContext messageContext) {

        boolean isRefreshTokenValid = (Boolean)messageContext.getParameter(IS_REFRESH_TOKEN_VALID);
        boolean markAccessTokenExpired = (Boolean)messageContext.getParameter(MARK_ACCESS_TOKEN_EXPIRED);
        AccessToken prevAccessToken = (AccessToken)messageContext.getParameter(OAuth2.PREV_ACCESS_TOKEN);
        String clientId = messageContext.getClientId();
        AuthenticatedUser authzUser = messageContext.getAuthzUser();
        Set<String> scopes = messageContext.getApprovedScopes();
        long accessTokenValidityPeriod = messageContext.getValidityPeriod();
        long refreshTokenValidityPeriod = messageContext.getValidityPeriod();
        String grantType = messageContext.getRequest().getGrantType();
        return issueNewAccessToken(clientId, authzUser, scopes, isRefreshTokenValid,
                markAccessTokenExpired, prevAccessToken, accessTokenValidityPeriod, refreshTokenValidityPeriod,
                grantType, messageContext);
    }

    protected abstract AccessToken issueNewAccessToken(String clientId, AuthenticatedUser authzUser, Set<String> scopes,
                                              boolean isRefreshTokenValid, boolean markAccessTokenExpired,
                                              AccessToken prevAccessToken, long accessTokenCallbackValidity,
                                              long refreshTokenCallbackValidity, String grantOrResponseType,
                                              OAuth2MessageContext messageContext);

    protected abstract void storeNewAccessToken(AccessToken accessToken, OAuth2MessageContext messageContext);


}
