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

/**
 * Implements the AuthorizationGrantHandler for the Grant Type : authorization_code.
 */
public class AuthorizationCodeGrantHandler extends AbstractAuthorizationGrantHandler {

    // This is used to keep the pre processed authorization code in the OAuthTokenReqMessageContext.
    private static final String AUTHZ_CODE = "AuthorizationCode";
    private static Log log = LogFactory.getLog(AuthorizationCodeGrantHandler.class);


    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        if (!super.validateGrant(tokReqMsgCtx)) {
            log.error("Invalid Token request message context");
            return false;
        }

        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        AuthzCodeDO authzCodeDO = getSavedAuthzCodeData(oAuth2AccessTokenReqDTO);

        if (!isAuthzCodeDataValid(authzCodeDO, oAuth2AccessTokenReqDTO.getClientId())) {
            return false;
        }

        // If redirect_uri was given in the authorization request,
        // token request should send matching redirect_uri value
        if (!isCallbackUrlValid(authzCodeDO.getCallbackUrl(), oAuth2AccessTokenReqDTO.getCallbackURI())) {

            if (log.isDebugEnabled()) {
                log.debug("Invalid redirect uri " + oAuth2AccessTokenReqDTO.getCallbackURI() +
                        " in the token request for client : " + oAuth2AccessTokenReqDTO.getClientId());
            }
            return false;
        }

        if (!isPKCEValid(authzCodeDO, oAuth2AccessTokenReqDTO.getPkceCodeVerifier())) {
            return false;
        }

        if (log.isDebugEnabled()) {
            log.debug("Found Authorization Code for Client : " + oAuth2AccessTokenReqDTO.getClientId() +
                    ", authorized user : " + authzCodeDO.getAuthorizedUser() +
                    ", scope : " + OAuth2Util.buildScopeString(authzCodeDO.getScope()));
        }

        tokReqMsgCtx.setAuthorizedUser(authzCodeDO.getAuthorizedUser());
        tokReqMsgCtx.setScope(authzCodeDO.getScope());
        // keep the pre processed authz code as a OAuthTokenReqMessageContext property to avoid
        // calculating it again when issuing the access token.
        tokReqMsgCtx.addProperty(AUTHZ_CODE, oAuth2AccessTokenReqDTO.getAuthorizationCode());
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
    private AuthzCodeDO getSavedAuthzCodeData(OAuth2AccessTokenReqDTO tokenReqDTO) throws IdentityOAuth2Exception {

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

    private boolean isCallbackUrlValid(String callbackUrlInAuthzRequest, String callbackUrlInTokenRequest) {

        if (StringUtils.isEmpty(callbackUrlInAuthzRequest)) {
            // If redirect_uri was not available in the authorization request,
            // no need to validate redirect_uri in the token request at this point
            return true;
        } else if (!callbackUrlInAuthzRequest.equals(callbackUrlInTokenRequest)) {
            return false;
        }
        return true;
    }

    /**
     * Checks whether the retrieved authorization data is invalid, inactive or expired.
     * Returns true otherwise
     *
     * @param authzCodeDO
     * @param clientId
     * @return
     * @throws IdentityOAuth2Exception
     */
    private boolean isAuthzCodeDataValid(AuthzCodeDO authzCodeDO, String clientId)
            throws IdentityOAuth2Exception {
        if (authzCodeDO == null) {
            // If no auth code details available, cannot proceed with Authorization code grant
            if(log.isDebugEnabled()) {
                log.debug("Invalid access token request with Client Id : " + clientId +
                        ", Invalid authorization code provided.");
            }
            return false;
        }
        if (OAuthConstants.AuthorizationCodeState.INACTIVE.equals(authzCodeDO.getState())) {
            if(log.isDebugEnabled()) {
                log.debug("Invalid access token request with Client Id : " + clientId +
                        ", Inactive authorization code provided.");
            }
            if (cacheEnabled) {
                String cacheKeyString = buildCacheKey(clientId, authzCodeDO);
                OAuthCache.getInstance().clearCacheEntry(new OAuthCacheKey(cacheKeyString));
            }
            return false;
        }
        if (isAuthzCodeExpired(authzCodeDO)) {
            return false;
        }
        return true;
    }

    private boolean isAuthzCodeExpired(AuthzCodeDO authzCodeDO)
            throws IdentityOAuth2Exception {
        long issuedTimeInMillis = authzCodeDO.getIssuedTime().getTime();
        long validityPeriodInMillis = authzCodeDO.getValidityPeriod();

        // If the code is not valid for more than 1 sec, it is considered to be expired
        if (OAuth2Util.calculateValidityInMillis(issuedTimeInMillis, validityPeriodInMillis) < 1000) {
            if(log.isDebugEnabled()) {
                log.debug("Authorization Code Issued Time(ms): " + issuedTimeInMillis +
                        ", Validity Period: " + validityPeriodInMillis + ", Timestamp Skew: " +
                        OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000 +
                        ", Current Time: " + System.currentTimeMillis());
            }

            // remove the authorization code from the database.
            tokenMgtDAO.changeAuthzCodeState(authzCodeDO.getAuthorizationCode(),
                    OAuthConstants.AuthorizationCodeState.EXPIRED);
            if (log.isDebugEnabled()) {
                log.debug("Expired Authorization code issued for client " + authzCodeDO.getConsumerKey() +
                        " was removed from the database.");
            }

            if (cacheEnabled) {
                // remove the authorization code from the cache
                OAuthCache.getInstance().clearCacheEntry(new OAuthCacheKey(
                        OAuth2Util.buildCacheKeyStringForAuthzCode(authzCodeDO.getConsumerKey(),
                                authzCodeDO.getAuthorizationCode())));
                if (log.isDebugEnabled()) {
                    log.debug("Expired Authorization code issued for client " + authzCodeDO.getConsumerKey() +
                            " was removed from the cache.");
                }
            }
            return true;
        }
        return false;
    }

    /**
     * Performs PKCE Validation for "Authorization Code" Grant Type
     *
     * @param authzCodeDO
     * @param codeVerifier
     * @return true if PKCE is validated
     * @throws IdentityOAuth2Exception
     */
    private boolean isPKCEValid(AuthzCodeDO authzCodeDO, String codeVerifier) throws IdentityOAuth2Exception {

        String PKCECodeChallenge = authzCodeDO.getPkceCodeChallenge();
        String PKCECodeChallengeMethod = authzCodeDO.getPkceCodeChallengeMethod();
        OAuthAppDO oAuthAppDO = getOAuthAppDO(authzCodeDO.getConsumerKey());
        if (!OAuth2Util.doPKCEValidation(PKCECodeChallenge, codeVerifier, PKCECodeChallengeMethod, oAuthAppDO)) {
            //possible malicious oAuthRequest
            log.warn("Failed PKCE Verification for oAuth 2.0 request");
            return false;
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
