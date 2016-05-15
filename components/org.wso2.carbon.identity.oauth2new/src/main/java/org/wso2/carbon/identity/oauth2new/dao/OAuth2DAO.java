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
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2TokenMessageContext;
import org.wso2.carbon.identity.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.oauth2new.model.AuthzCode;
import org.wso2.carbon.identity.oauth2new.revoke.RevocationMessageContext;

import java.util.Set;

/*
 * To interact with the persistence layer
 */
public abstract class OAuth2DAO {

    public abstract AccessToken getLatestActiveOrExpiredAccessToken(String consumerKey, AuthenticatedUser authzUser,
                                                                    Set<String> scopes,
                                                                    OAuth2MessageContext messageContext);

    public abstract void storeAccessToken(AccessToken newAccessToken, String oldAccessToken, String authzCode,
                                          OAuth2MessageContext messageContext);

    public abstract String getAccessTokenByAuthzCode(String authorizationCode, OAuth2MessageContext messageContext);

    public abstract void updateAccessTokenState(String accessToken, String tokenState,
                                                OAuth2TokenMessageContext messageContext);

    public abstract AccessToken getLatestAccessTokenByRefreshToken(String refreshToken,
                                                                   OAuth2MessageContext messageContext);

    public abstract void storeAuthzCode(AuthzCode authzCode, OAuth2MessageContext messageContext);

    public abstract AuthzCode getAuthzCode(String authzCode, OAuth2MessageContext messageContext);

    public abstract void updateAuthzCodeState(String authzCode, String state, OAuth2MessageContext messageContext);

    public abstract Set<String> getAuthorizedClientIDs(AuthenticatedUser authzUser,
                                                       RevocationMessageContext messageContext);

    public abstract AccessToken getAccessToken(String bearerToken, OAuth2MessageContext messageContext);

    public abstract void revokeAccessToken(String accessToken, RevocationMessageContext messageContext);

    public abstract void revokeRefreshToken(String refreshToken, RevocationMessageContext messageContext);

}
