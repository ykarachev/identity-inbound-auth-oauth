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
import org.apache.axiom.util.base64.Base64Utils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.model.User;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth.model.context.MessageContext;
import org.wso2.carbon.identity.oauth.util.OAuthUtil;

import java.sql.Timestamp;
import java.util.Date;
import java.util.Set;

public class UserAssertedResponseIssuer extends BearerTokenResponseIssuer {

    private static Log log = LogFactory.getLog(UserAssertedResponseIssuer.class);

    public AccessTokenDO issueNewToken(String clientId, String redirectURI, User authzUser, long callbackValidityPeriod,
                                       Set<String> approvedScopes, String tokenUserType, MessageContext messageContext)
            throws OAuthSystemException {

        AccessTokenDO accessTokenDO = null;
        if (log.isDebugEnabled()) {
            log.debug("Issuing a new access token for client Id : " + clientId +
                    " authorized by : " + authzUser.toString());
        }

        String accessToken = null;
        String refreshToken = null;
        try {
            accessToken = oauthIssuerImpl.accessToken();
            String tokenStr = accessToken + ":" + authzUser.toString();
            accessToken = Base64Utils.encode(tokenStr.getBytes());
            if(issueRefreshToken(messageContext)){
                refreshToken = oauthIssuerImpl.refreshToken();
                tokenStr = refreshToken + ":" + authzUser.toString();
                refreshToken = Base64Utils.encode(tokenStr.getBytes());
            }
        } catch (OAuthSystemException e) {
            log.debug(e.getMessage(), e);
            throw new OAuthSystemException("Error occurred while generating access token and refresh token " +
                    "for clientId : " + clientId + " and authorized user : " + authzUser.toString());
        }

        Timestamp timestamp = new Timestamp(new Date().getTime());
        // Default Validity Period
        long validityPeriod = OAuthServerConfiguration.getInstance().getUserAccessTokenValidityPeriodInSeconds();
        // if a VALID validity period is set through the callback, then use it
        if ((callbackValidityPeriod != OAuthConstants.UNASSIGNED_VALIDITY_PERIOD) && callbackValidityPeriod > 0) {
            validityPeriod = callbackValidityPeriod;
        }

        // convert to milliseconds
        validityPeriod = validityPeriod * 1000;

        accessTokenDO = new AccessTokenDO(accessToken, clientId, authzUser, approvedScopes,
                OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE, timestamp, validityPeriod,
                OAuthConstants.UserType.USER_TYPE_FOR_USER_TOKEN);
        accessTokenDO.setRefreshToken(refreshToken);

        // Persist the access token in database
        oauthDAO.storeAccessToken(accessTokenDO, messageContext);

        if (log.isDebugEnabled()) {
            log.debug("Persisted an access token with " +
                    "Client ID : " + clientId +
                    "Authorized User : " + authzUser.toString() +
                    "Issuer Timestamp : " + timestamp +
                    "Validity Period : " + validityPeriod +
                    "Scopes : " + OAuthUtil.buildScopeString(approvedScopes) +
                    "Redirect URI : " + redirectURI +
                    "Token State : " + OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE +
                    "User Type : " + tokenUserType);
        }

        return accessTokenDO;
    }

}
