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

package org.wso2.carbon.identity.oauth2new.cache;

import org.wso2.carbon.identity.application.common.cache.BaseCache;
import org.wso2.carbon.identity.oauth2new.listener.OAuth2CacheListener;
import org.wso2.carbon.identity.oauth2new.model.AccessToken;
import org.wso2.carbon.utils.CarbonUtils;

/**
 * To cache OAuth2 access token information against client ID, authorized user and approved scope.
 */
public class AuthorizationGrantCache extends BaseCache<AuthorizationGrantCacheKey, AccessToken> {

    private static final String OAUTH2_AUTHORIZATION_GRANT_CACHE_NAME = "OAuth2AuthorizationGrantCache";

    private static volatile AuthorizationGrantCache instance;

    private AuthorizationGrantCache() {
        super(OAUTH2_AUTHORIZATION_GRANT_CACHE_NAME);
        super.addListener(new OAuth2CacheListener());
    }

    public static AuthorizationGrantCache getInstance() {
        CarbonUtils.checkSecurity();
        if (instance == null) {
            synchronized (AuthorizationGrantCache.class) {
                if (instance == null) {
                    instance = new AuthorizationGrantCache();
                }
            }
        }
        return instance;
    }
}
