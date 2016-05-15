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

package org.wso2.carbon.identity.oauth2new.util;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.oauth2new.model.OAuth2ServerConfig;

import java.util.HashSet;
import java.util.Set;

public class OAuth2Util {

    public static Set<String> buildScopeSet(String scopes) {
        Set<String> scopeSet = new HashSet<>();
        if (StringUtils.isNotBlank(scopes)) {
            String[] scopeArray = scopes.split("\\s");
            for(String scope:scopeArray){
                if(StringUtils.isNotBlank(scope)) {
                    scopeSet.add(scope);
                }
            }
        }
        return scopeSet;
    }

    public static String buildScopeString(Set<String> scopes) {
        StringBuilder builder = new StringBuilder("");
        if(CollectionUtils.isNotEmpty(scopes)) {
            for (String scope : scopes) {
                if (StringUtils.isNotBlank(scope)) {
                    builder.append(scope);
                    builder.append(" ");
                }
            }
            if (builder.charAt(builder.length() - 1) == ' ') {
                builder.substring(0, builder.charAt(builder.length() - 1));
            }
        }
        return builder.toString();
    }

    public static String hashScopes(Set<String> scopes){
        return hashScopes(buildScopeString(scopes));
    }

    public static String hashScopes(String scopes){
        if (scopes != null) {
            return DigestUtils.md5Hex(scopes);
        }
        throw new IllegalArgumentException("Scopes are NULL");
    }

    public static long getTokenValidityPeriod(AccessToken accessToken) {

        if (accessToken == null) {
            throw new IllegalArgumentException("AccessToken is NULL");
        }

        long accessTokenValidityPeriodMillis = accessToken.getAccessTokenValidity();

        if(accessTokenValidityPeriodMillis < 0) {
            return -1;
        }

        long skew = OAuth2ServerConfig.getInstance().getTimeStampSkew();

        long accessTokenIssuedTime = accessToken.getAccessTokenIssuedTime().getTime();
        long refreshTokenIssuedTime = accessToken.getRefreshTokenIssuedTime().getTime();
        long currentTime = System.currentTimeMillis();
        long refreshTokenValidityPeriodMillis = accessToken.getRefreshTokenValidity();
        long remainingAccessTokenValidity = accessTokenIssuedTime + accessTokenValidityPeriodMillis - (currentTime +
                skew);
        long remainingRefreshTokenValidity = (refreshTokenIssuedTime + refreshTokenValidityPeriodMillis) -
                (currentTime + skew);
        if(remainingAccessTokenValidity > 1000 && remainingRefreshTokenValidity > 1000){
            return remainingAccessTokenValidity;
        }
        return 0;
    }

    public static long getRefreshTokenValidityPeriod(AccessToken accessToken) {

        if (accessToken == null) {
            throw new IllegalArgumentException("AccessToken is NULL");
        }

        long skew = OAuth2ServerConfig.getInstance().getTimeStampSkew();
        long refreshTokenValidity = accessToken.getRefreshTokenValidity();
        long currentTime = System.currentTimeMillis();
        long refreshTokenIssuedTime = accessToken.getRefreshTokenIssuedTime().getTime();
        long remainingRefreshTokenValidity = (refreshTokenIssuedTime + refreshTokenValidity)
                - (currentTime + skew);
        if(remainingRefreshTokenValidity > 1000){
            return remainingRefreshTokenValidity;
        }
        return 0;
    }

    public static long getAccessTokenValidityPeriod(AccessToken accessToken) {

        if(accessToken == null){
            throw new IllegalArgumentException("AccessToken is NULL");
        }

        long validityPeriod = accessToken.getAccessTokenValidity();
        if (validityPeriod < 0) {
            return -1;
        }
        long timestampSkew = OAuth2ServerConfig.getInstance().getTimeStampSkew() * 1000;
        long issuedTime = accessToken.getAccessTokenIssuedTime().getTime();
        long currentTime = System.currentTimeMillis();
        long remainingValidity = issuedTime + validityPeriod - (currentTime + timestampSkew);
        if (remainingValidity > 1000) {
            return remainingValidity;
        } else {
            return 0;
        }
    }

    public static String createUniqueAuthzGrantString(AuthenticatedUser authzUser, String clientId,
                                                      Set<String> scopes) {
        if(authzUser == null || StringUtils.isBlank(clientId)){
            throw new IllegalArgumentException("Invalid arguments: AuthenticatedUser is " + authzUser + " and " +
                    "clientId is " + clientId);
        }
        StringBuilder builder = new StringBuilder("");
        builder.append(authzUser.toString()).append(":").append(clientId);
        if(!scopes.isEmpty()){
            builder.append(":").append(OAuth2Util.buildScopeString(scopes));
        }
        return builder.toString();
    }
}
