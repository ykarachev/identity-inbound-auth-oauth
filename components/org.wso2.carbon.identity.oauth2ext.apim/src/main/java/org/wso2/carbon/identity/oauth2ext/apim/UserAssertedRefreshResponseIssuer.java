/*
*Copyright (c) 2005-2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*WSO2 Inc. licenses this file to you under the Apache License,
*Version 2.0 (the "License"); you may not use this file except
*in compliance with the License.
*You may obtain a copy of the License at
*
*http://www.apache.org/licenses/LICENSE-2.0
*
*Unless required by applicable law or agreed to in writing,
*software distributed under the License is distributed on an
*"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
*KIND, either express or implied.  See the License for the
*specific language governing permissions and limitations
*under the License.
*/

package org.wso2.carbon.identity.oauth2ext.apim;

import org.apache.amber.oauth2.common.exception.OAuthSystemException;
import org.apache.amber.oauth2.common.message.types.TokenType;
import org.apache.axiom.util.base64.Base64Utils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.model.User;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth.model.context.MessageContext;
import org.wso2.carbon.identity.oauth.model.context.TokenMessageContext;
import org.wso2.carbon.identity.oauth.model.message.response.ResponseHeader;
import org.wso2.carbon.identity.oauth.model.message.response.TokenBearerResponse;
import org.wso2.carbon.identity.oauth.util.OAuthUtil;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Date;
import java.util.Set;

public class UserAssertedRefreshResponseIssuer extends RefreshBearerTokenResponseIssuer {

    private static Log log = LogFactory.getLog(UserAssertedRefreshResponseIssuer.class);

    private static final String PREV_ACCESS_TOKEN = "previousAccessToken";

    @Override
    public TokenBearerResponse issueResponse(MessageContext messageContext) throws OAuthSystemException {

        TokenMessageContext tokenMessageContext = (TokenMessageContext)messageContext;

        String accessToken = null;
        String refreshToken = null;
        try {
            accessToken = oauthIssuerImpl.accessToken();
            String tokenStr = accessToken + ":" + ((TokenMessageContext) messageContext).getAuthzUser().toString();
            accessToken = Base64Utils.encode(tokenStr.getBytes());
            if(issueRefreshToken(messageContext)){
                refreshToken = oauthIssuerImpl.refreshToken();
                tokenStr = refreshToken + ":" + ((TokenMessageContext) messageContext).getAuthzUser().toString();
                refreshToken = Base64Utils.encode(tokenStr.getBytes());
            }
        } catch (OAuthSystemException e) {
            log.debug(e.getMessage(), e);
            throw new OAuthSystemException("Error occurred while generating access token and refresh token " +
                    "for clientId : " + tokenMessageContext.getClientId());
        }

        Timestamp timestamp = new Timestamp(new Date().getTime());

        // Default Validity Period (in seconds)
        long validityPeriod = OAuthServerConfiguration.getInstance()
                .getUserAccessTokenValidityPeriodInSeconds();

        // if a VALID validity period is set through the callback, then use it
        long callbackValidityPeriod = ((TokenMessageContext)messageContext).getValidityPeriod();
        if ((callbackValidityPeriod != OAuthConstants.UNASSIGNED_VALIDITY_PERIOD) && callbackValidityPeriod > 0) {
            validityPeriod = callbackValidityPeriod;
        }

        // convert to milliseconds
        validityPeriod = validityPeriod * 1000;

        String tokenUserType = getAuthzUserType(messageContext);

        AccessTokenDO accessTokenDO = new AccessTokenDO(accessToken, tokenMessageContext.getClientId(),
                tokenMessageContext.getAuthzUser(), tokenMessageContext.getApprovedScope(),
                OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE,
                timestamp, validityPeriod, tokenUserType);
        accessTokenDO.setRefreshToken(refreshToken);

        String clientId = tokenMessageContext.getClientId();
        String oldAccessToken = (String)messageContext.getProperty(PREV_ACCESS_TOKEN);
        User authzUser = tokenMessageContext.getAuthzUser();
        Set<String> approvedScopes = tokenMessageContext.getApprovedScope();

        // set the previous access token state to "INACTIVE"
        oauthDAO.updateAccessTokenState(clientId, authzUser, approvedScopes,
                OAuthConstants.TokenStates.TOKEN_STATE_INACTIVE);

        // store the new access token
        oauthDAO.storeAccessToken(accessTokenDO, messageContext);

        if (log.isDebugEnabled()) {
            log.debug("Issued an access token for the refresh token, " +
                    "Client ID : " + clientId +
                    "authorized user : " + ((TokenMessageContext) messageContext).getAuthzUser() +
                    "timestamp : " + timestamp +
                    "validity period : " + validityPeriod +
                    "scope : " + OAuthUtil.buildScopeString(tokenMessageContext.getApprovedScope()) +
                    "Token State : " + OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE +
                    "User Type : " + tokenUserType);
        }

        TokenBearerResponse tokenBearerResponse = new TokenBearerResponse(
                TokenType.BEARER.toString(), validityPeriod, accessToken);
        tokenBearerResponse.setRefreshToken(refreshToken);
        tokenBearerResponse.setApprovedScopes(tokenMessageContext.getApprovedScope());

        ArrayList<ResponseHeader> respHeaders = new ArrayList<ResponseHeader>();
        ResponseHeader header = new ResponseHeader();
        header.setKey("DeactivatedAccessToken");
        header.setValue(oldAccessToken);
        respHeaders.add(header);

        messageContext.addProperty("RESPONSE_HEADERS", respHeaders.toArray(
                new ResponseHeader[respHeaders.size()]));

        return tokenBearerResponse;
    }

}
