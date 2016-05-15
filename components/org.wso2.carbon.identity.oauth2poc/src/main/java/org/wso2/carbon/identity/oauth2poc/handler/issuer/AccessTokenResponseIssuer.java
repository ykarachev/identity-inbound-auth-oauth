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

package org.wso2.carbon.identity.oauth2poc.handler.issuer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.oauth2poc.OAuth2;
import org.wso2.carbon.identity.oauth2poc.bean.context.OAuth2AuthzMessageContext;
import org.wso2.carbon.identity.oauth2poc.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.oauth2poc.exception.OAuth2Exception;
import org.wso2.carbon.identity.oauth2poc.exception.OAuth2RuntimeException;
import org.wso2.carbon.identity.oauth2poc.model.AccessToken;

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
        } else {
            throw OAuth2RuntimeException.error("Invalid OAuth2MessageContext - unknown sub type");
        }
    }

    protected AccessToken validTokenExists(OAuth2AuthzMessageContext messageContext) {

        String clientId = messageContext.getRequest().getClientId();
        AuthenticatedUser authzUser = messageContext.getAuthzUser();
        Set<String> scopes = messageContext.getApprovedScopes();
        return validTokenExists(clientId, authzUser, scopes, messageContext);
    }

    protected AccessToken validTokenExists(String clientId, AuthenticatedUser authzUser,
                                           Set<String> scopes, OAuth2MessageContext messageContext) {

        boolean isAccessTokenValid = false;
        boolean isRefreshTokenValid = false;
        boolean markAccessTokenExpired = false;

        // check in cache and persistent storage
        AccessToken accessToken = null;

        messageContext.addParameter(IS_ACCESS_TOKEN_VALID, isAccessTokenValid);
        messageContext.addParameter(IS_REFRESH_TOKEN_VALID, isRefreshTokenValid);
        messageContext.addParameter(MARK_ACCESS_TOKEN_EXPIRED, markAccessTokenExpired);
        messageContext.addParameter(OAuth2.PREV_ACCESS_TOKEN, accessToken);

        return accessToken;
    }

    protected AccessToken issueNewAccessToken(OAuth2MessageContext messageContext) {

        if(messageContext instanceof OAuth2AuthzMessageContext) {
            return issueNewAccessToken((OAuth2AuthzMessageContext) messageContext);
        } else {
            throw OAuth2RuntimeException.error("Invalid OAuth2MessageContext - unknown sub type");
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

    protected abstract AccessToken issueNewAccessToken(String clientId, AuthenticatedUser authzUser, Set<String> scopes,
                                              boolean isRefreshTokenValid, boolean markAccessTokenExpired,
                                              AccessToken prevAccessToken, long accessTokenCallbackValidity,
                                              long refreshTokenCallbackValidity, String grantOrResponseType,
                                              OAuth2MessageContext messageContext);

    protected abstract void storeNewAccessToken(AccessToken accessToken, OAuth2MessageContext messageContext);


}
