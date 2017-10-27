/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.token.handlers.grant;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.getTimeToExpire;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.validatePKCE;

/**
 * Implements the AuthorizationGrantHandler for the Grant Type : authorization_code.
 */
public class AuthorizationCodeGrantHandler extends AbstractAuthorizationGrantHandler {

    // This is used to keep the pre processed authorization code in the OAuthTokenReqMessageContext.
    private static final String AUTHZ_CODE = "AuthorizationCode";
    public static final int ALLOWED_MINIMUM_VALIDITY_PERIOD = 1000;
    private static Log log = LogFactory.getLog(AuthorizationCodeGrantHandler.class);

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
        super.validateGrant(tokReqMsgCtx);
        OAuth2AccessTokenReqDTO tokenReq = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        AuthzCodeDO authzCodeBean = getPersistedAuthzCode(tokenReq);

        validateAuthzCodeFromRequest(authzCodeBean, tokenReq.getClientId(), tokenReq.getAuthorizationCode());
        // If redirect_uri was given in the authorization request,
        // token request should send matching redirect_uri value
        validateCallbackUrlFromRequest(tokenReq.getCallbackURI(), authzCodeBean.getCallbackUrl());
        validatePKCECode(authzCodeBean, tokenReq.getPkceCodeVerifier());
        if (log.isDebugEnabled()) {
            log.debug("Found Authorization Code for Client : " + tokenReq.getClientId() +
                    ", authorized user : " + authzCodeBean.getAuthorizedUser() +
                    ", scope : " + OAuth2Util.buildScopeString(authzCodeBean.getScope()));
        }

        setPropertiesForTokenGeneration(tokReqMsgCtx, tokenReq, authzCodeBean);
        return true;
    }

    private void setPropertiesForTokenGeneration(OAuthTokenReqMessageContext tokReqMsgCtx,
                                                 OAuth2AccessTokenReqDTO tokenReq, AuthzCodeDO authzCodeBean) {
        tokReqMsgCtx.setAuthorizedUser(authzCodeBean.getAuthorizedUser());
        tokReqMsgCtx.setScope(authzCodeBean.getScope());
        // keep the pre processed authz code as a OAuthTokenReqMessageContext property to avoid
        // calculating it again when issuing the access token.
        tokReqMsgCtx.addProperty(AUTHZ_CODE, tokenReq.getAuthorizationCode());
    }

    private boolean validateCallbackUrlFromRequest(String callbackUrlFromRequest,
                                                   String callbackUrlFromPersistedAuthzCode)
            throws IdentityOAuth2Exception {
        if (StringUtils.isEmpty(callbackUrlFromPersistedAuthzCode)) {
            return true;
        }

        if (!callbackUrlFromPersistedAuthzCode.equals(callbackUrlFromRequest)) {
            if (log.isDebugEnabled()) {
                log.debug("Received callback url in the request : " + callbackUrlFromRequest +
                        " is not matching with persisted callback url " + callbackUrlFromPersistedAuthzCode);
            }
            throw new IdentityOAuth2Exception("Callback url mismatch");
        }
        return true;
    }

    @Override
    public OAuth2AccessTokenRespDTO issue(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {
        OAuth2AccessTokenRespDTO tokenRespDTO = super.issue(tokReqMsgCtx);

        // get the token from the OAuthTokenReqMessageContext which is stored while validating
        // the authorization code.
        String authzCode = (String) tokReqMsgCtx.getProperty(AUTHZ_CODE);
        boolean existingTokenUsed = false;
        if (tokReqMsgCtx.getProperty(EXISTING_TOKEN_ISSUED) != null) {
            existingTokenUsed = (Boolean) tokReqMsgCtx.getProperty(EXISTING_TOKEN_ISSUED);
        }
        // if it's not there (which is unlikely), recalculate it.
        if (authzCode == null) {
            authzCode = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getAuthorizationCode();
        }

        try {
            if (existingTokenUsed){
                // has given an already issued access token. So the authorization code is not deactivated yet
                tokenMgtDAO.deactivateAuthorizationCode(authzCode, tokenRespDTO.getTokenId());
            }
        } catch (IdentityException e) {
            throw new IdentityOAuth2Exception("Error occurred while deactivating authorization code", e);
        }

        // Clear the cache entry
        if (cacheEnabled) {
            String clientId = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId();
            OAuthCacheKey cacheKey = new OAuthCacheKey(OAuth2Util.buildCacheKeyStringForAuthzCode(
                    clientId, authzCode));
            OAuthCache.getInstance().clearCacheEntry(cacheKey);

            if (log.isDebugEnabled()) {
                log.debug("Cache was cleared for authorization code info for client id : " + clientId);
            }
        }

        return tokenRespDTO;
    }

    @Override
    public boolean authorizeAccessDelegation(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {
        // authorization is handled when the authorization code was issued.
        return true;
    }

    @Override
    protected void storeAccessToken(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO, String userStoreDomain,
                                    AccessTokenDO newAccessTokenDO, String newAccessToken, AccessTokenDO
                                                existingAccessTokenDO)
            throws IdentityOAuth2Exception {
        try {
            newAccessTokenDO.setAuthorizationCode(oAuth2AccessTokenReqDTO.getAuthorizationCode());
            tokenMgtDAO.storeAccessToken(newAccessToken, oAuth2AccessTokenReqDTO.getClientId(),
                                         newAccessTokenDO, existingAccessTokenDO, userStoreDomain);
        } catch (IdentityException e) {
            throw new IdentityOAuth2Exception(
                    "Error occurred while storing new access token", e);
        }
    }

    @Override
    public boolean issueRefreshToken() throws IdentityOAuth2Exception {

        return OAuthServerConfiguration.getInstance()
                .getValueForIsRefreshTokenAllowed(OAuthConstants.GrantTypes.AUTHORIZATION_CODE);
    }

    /**
     * Provides authorization code request details saved in cache or DB
     * @param tokenReqDTO
     * @return
     * @throws IdentityOAuth2Exception
     */
    private AuthzCodeDO getPersistedAuthzCode(OAuth2AccessTokenReqDTO tokenReqDTO) throws IdentityOAuth2Exception {

        AuthzCodeDO authzCodeDO;
        // If cache is enabled, check in the cache first.
        if (cacheEnabled) {
            OAuthCacheKey cacheKey = new OAuthCacheKey(OAuth2Util.buildCacheKeyStringForAuthzCode(
                    tokenReqDTO.getClientId(), tokenReqDTO.getAuthorizationCode()));
            authzCodeDO = (AuthzCodeDO) OAuthCache.getInstance().getValueFromCache(cacheKey);
            if (authzCodeDO != null) {
                return authzCodeDO;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Authorization Code Info was not available in cache for client id : "
                            + tokenReqDTO.getClientId());
                }
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Retrieving authorization code information from db for client id : " + tokenReqDTO.getClientId());
        }
        return tokenMgtDAO.validateAuthorizationCode(tokenReqDTO.getClientId(), tokenReqDTO.getAuthorizationCode());
    }

    private String buildCacheKey(String clientId, AuthzCodeDO authzCodeDO) {
        String scope = OAuth2Util.buildScopeString(authzCodeDO.getScope());
        String authorizedUser = authzCodeDO.getAuthorizedUser().toString();
        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authorizedUser);
        if (isUsernameCaseSensitive) {
            return clientId + ":" + authorizedUser + ":" + scope;
        } else {
            return clientId + ":" + authorizedUser.toLowerCase() + ":" + scope;
        }
    }

    /**
     * Checks whether the retrieved authorization data is invalid, inactive or expired.
     * Returns true otherwise
     *
     * @param authzCodeBean
     * @param clientId
     * @return
     * @throws IdentityOAuth2Exception
     */
    private boolean validateAuthzCodeFromRequest(AuthzCodeDO authzCodeBean, String clientId, String authzCode)
            throws IdentityOAuth2Exception {
        if (authzCodeBean == null) {
            // If no auth code details available, cannot proceed with Authorization code grant
            if(log.isDebugEnabled()) {
                log.debug("Invalid token request for client id: " + clientId +
                        "and couldn't find persisted data for authorization code: " + authzCode);
            }
           throw new IdentityOAuth2Exception("Invalid authorization code received from token request");
        }

        if (isIncativeAuthzCode(authzCodeBean)) {
            removeIfCached(authzCodeBean, clientId);
            throw new IdentityOAuth2Exception("Inactive authorization code received from token request");
        }

        if (isAuthzCodeExpired(authzCodeBean)) {
            throw new IdentityOAuth2Exception("Expired authorization code received from token request");
        }
        return true;
    }

    private void removeIfCached(AuthzCodeDO authzCodeBean, String clientId) {
        if (cacheEnabled) {
            String cacheKeyString = buildCacheKey(clientId, authzCodeBean);
            OAuthCache.getInstance().clearCacheEntry(new OAuthCacheKey(cacheKeyString));
            if(log.isDebugEnabled()) {
                log.debug("Removed inactive authz code : " + authzCodeBean.getAuthorizationCode() + " from cache");
            }
        }
    }

    private boolean isIncativeAuthzCode(AuthzCodeDO authzCodeBean) {
        if (OAuthConstants.AuthorizationCodeState.INACTIVE.equals(authzCodeBean.getState())) {
            if(log.isDebugEnabled()) {
                log.debug("Invalid access token request with Client Id : " + authzCodeBean.getConsumerKey() +
                        ", Inactive authorization code : " + authzCodeBean.getAuthorizationCode());
            }
            return true;
        }
        return false;
    }

    private boolean isAuthzCodeExpired(AuthzCodeDO authzCodeBean)
            throws IdentityOAuth2Exception {
        long issuedTime = authzCodeBean.getIssuedTime().getTime();
        long validityPeriod = authzCodeBean.getValidityPeriod();

        // If the code is not valid for more than 1 sec, it is considered to be expired
        if (getTimeToExpire(issuedTime, validityPeriod) < ALLOWED_MINIMUM_VALIDITY_PERIOD) {
            markAsExpired(authzCodeBean);
            if(log.isDebugEnabled()) {
                log.debug("Authorization Code Issued Time(ms): " + issuedTime +
                        ", Validity Period: " + validityPeriod + ", Timestamp Skew: " +
                        OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000 +
                        ", Current Time: " + System.currentTimeMillis());
            }
            return true;
        }
        return false;
    }

    private void markAsExpired(AuthzCodeDO authzCodeBean) throws IdentityOAuth2Exception {
        tokenMgtDAO.changeAuthzCodeState(authzCodeBean.getAuthorizationCode(),
                OAuthConstants.AuthorizationCodeState.EXPIRED);
        if (log.isDebugEnabled()) {
            log.debug("Changed state of authorization code : " + authzCodeBean.getAuthorizationCode() + " to expired");
        }

        if (cacheEnabled) {
            // remove the authorization code from the cache
            OAuthCache.getInstance().clearCacheEntry(new OAuthCacheKey(
                    OAuth2Util.buildCacheKeyStringForAuthzCode(authzCodeBean.getConsumerKey(),
                            authzCodeBean.getAuthorizationCode())));
            if (log.isDebugEnabled()) {
                log.debug("Expired Authorization code issued for client " + authzCodeBean.getConsumerKey() +
                        " was removed from the cache.");
            }
        }
    }

    /**
     * Performs PKCE Validation for "Authorization Code" Grant Type
     *
     * @param authzCodeBean
     * @param verificationCode
     * @return true if PKCE is validated
     * @throws IdentityOAuth2Exception
     */
    private boolean validatePKCECode(AuthzCodeDO authzCodeBean, String verificationCode) throws IdentityOAuth2Exception {
        String PKCECodeChallenge = authzCodeBean.getPkceCodeChallenge();
        String PKCECodeChallengeMethod = authzCodeBean.getPkceCodeChallengeMethod();
        OAuthAppDO oAuthApp = getOAuthAppDO(authzCodeBean.getConsumerKey());
        if (!validatePKCE(PKCECodeChallenge, verificationCode, PKCECodeChallengeMethod, oAuthApp)) {
            //possible malicious oAuthRequest
            log.warn("Failed PKCE Verification for oAuth 2.0 request");
            if (log.isDebugEnabled()) {
                log.debug("PKCE code verification failed for client : " + authzCodeBean.getConsumerKey());
            }
            throw new IdentityOAuth2Exception("PKCE validation failed");
        }
        return true;
    }

    private OAuthAppDO getOAuthAppDO(String clientId) throws IdentityOAuth2Exception {
        OAuthAppDO oAuthAppDO = AppInfoCache.getInstance().getValueFromCache(clientId);
        if (oAuthAppDO == null) {
            if (log.isDebugEnabled()) {
                log.debug("App information not found in cache for client id: " + clientId);
            }
            try {
                oAuthAppDO = new OAuthAppDAO().getAppInformation(clientId);
            } catch (InvalidOAuthClientException e) {
                throw new IdentityOAuth2Exception("Invalid OAuth client", e);
            }
            AppInfoCache.getInstance().addToCache(clientId, oAuthAppDO);
        }
        return oAuthAppDO;
    }
}
