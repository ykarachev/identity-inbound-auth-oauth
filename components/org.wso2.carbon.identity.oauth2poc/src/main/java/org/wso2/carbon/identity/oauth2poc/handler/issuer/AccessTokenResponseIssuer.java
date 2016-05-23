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
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.processor.request.AuthenticationRequest;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.oauth2poc.OAuth2;
import org.wso2.carbon.identity.oauth2poc.bean.message.request.authz.OAuth2AuthzRequest;
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
    public AccessToken issue(AuthenticationContext messageContext) {

        AccessToken accessToken = validTokenExists(messageContext);
        boolean isAccessTokenValid = (Boolean)messageContext.getParameter(IS_ACCESS_TOKEN_VALID);
        boolean isRefreshTokenValid = (Boolean)messageContext.getParameter(IS_REFRESH_TOKEN_VALID);
        if(!isAccessTokenValid || !isRefreshTokenValid) {
            accessToken = issueNewAccessToken(messageContext);
            storeNewAccessToken(accessToken, messageContext);
        }
        return accessToken;
    }

    protected AccessToken validTokenExists(AuthenticationContext messageContext) {

        AuthenticationRequest request = messageContext.getInitialAuthenticationRequest();
        if(request instanceof OAuth2AuthzRequest) {
            OAuth2AuthzRequest authzRequest = (OAuth2AuthzRequest)request;
            return validTokenExists(authzRequest, messageContext);
        } else {
            throw OAuth2RuntimeException.error("Invalid AuthenticationRequest - unknown sub type");
        }
    }

    protected AccessToken validTokenExists(OAuth2AuthzRequest authzRequest, AuthenticationContext messageContext) {

        String clientId = authzRequest.getClientId();
        // The final authenticated user should be obtained here
        AuthenticatedUser user = null;
        Set<String> approvedScopes = (Set<String>)messageContext.getParameter("ApprovedScopes");
        return validTokenExists(clientId, user, approvedScopes, messageContext);
    }

    protected AccessToken validTokenExists(String clientId, AuthenticatedUser user,
                                           Set<String> scopes, AuthenticationContext messageContext) {

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

    protected AccessToken issueNewAccessToken(AuthenticationContext messageContext) {

        AuthenticationRequest request = messageContext.getInitialAuthenticationRequest();
        if(request instanceof OAuth2AuthzRequest) {
            OAuth2AuthzRequest authzRequest = (OAuth2AuthzRequest)request;
            return issueNewAccessToken(authzRequest, messageContext);
        } else {
            throw OAuth2RuntimeException.error("Invalid AuthenticationRequest - unknown sub type");
        }
    }

    protected AccessToken issueNewAccessToken(OAuth2AuthzRequest authzRequest, AuthenticationContext messageContext) {

        boolean isRefreshTokenValid = (Boolean)messageContext.getParameter(IS_REFRESH_TOKEN_VALID);
        boolean markAccessTokenExpired = (Boolean)messageContext.getParameter(MARK_ACCESS_TOKEN_EXPIRED);
        AccessToken prevAccessToken = (AccessToken)messageContext.getParameter(OAuth2.PREV_ACCESS_TOKEN);
        String clientId = authzRequest.getClientId();
        // The final authenticated user should be obtained here
        AuthenticatedUser user = null;
        Set<String> approvedScopes = (Set<String>)messageContext.getParameter("ApprovedScopes");
        long accessTokenCallbackValidity = (Long)messageContext.getParameter("AccessTokenValidityPeriod");
        long refreshTokenCallbackValidity = (Long)messageContext.getParameter("RefreshTokenValidityPeriod");
        String responseType = authzRequest.getResponseType();
        return issueNewAccessToken(clientId, user, approvedScopes, isRefreshTokenValid,
                markAccessTokenExpired, prevAccessToken, accessTokenCallbackValidity, refreshTokenCallbackValidity,
                responseType, messageContext);
    }

    protected abstract AccessToken issueNewAccessToken(String clientId, AuthenticatedUser authzUser, Set<String> scopes,
                                              boolean isRefreshTokenValid, boolean markAccessTokenExpired,
                                              AccessToken prevAccessToken, long accessTokenCallbackValidity,
                                              long refreshTokenCallbackValidity, String grantOrResponseType,
                                              AuthenticationContext messageContext);

    protected abstract void storeNewAccessToken(AccessToken accessToken, AuthenticationContext messageContext);


}
