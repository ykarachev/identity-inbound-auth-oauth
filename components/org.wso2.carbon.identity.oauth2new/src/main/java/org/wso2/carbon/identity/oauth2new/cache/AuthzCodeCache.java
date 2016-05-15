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
import org.wso2.carbon.identity.oauth2new.model.AuthzCode;
import org.wso2.carbon.utils.CarbonUtils;

/**
 * To cache OAuth2 authorization code information.
 */
public class AuthzCodeCache extends BaseCache<String, AuthzCode> {

    private static final String OAUTH2_AUTHZ_CODE_CACHE_NAME = "OAuth2AuthzCodeCache";

    private static volatile AuthzCodeCache instance;

    private AuthzCodeCache() {
        super(OAUTH2_AUTHZ_CODE_CACHE_NAME);
    }

    public static AuthzCodeCache getInstance() {
        CarbonUtils.checkSecurity();
        if (instance == null) {
            synchronized (AuthzCodeCache.class) {
                if (instance == null) {
                    instance = new AuthzCodeCache();
                }
            }
        }
        return instance;
    }
}
