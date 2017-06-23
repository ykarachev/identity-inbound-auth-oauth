/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.oauth.cache;

import org.wso2.carbon.identity.application.common.cache.BaseCache;
import org.wso2.carbon.identity.oauth2.bean.Scope;

/**
 * OauthScopeCache is used to cache scope binding information.
 */
public class OauthScopeCache extends BaseCache<String, Scope> {

    private static final String OAUTH_SCOPE_CACHE_NAME = "OauthScopeCache";
    private static volatile OauthScopeCache instance;

    private OauthScopeCache() {
        super(OAUTH_SCOPE_CACHE_NAME);
    }

    public static OauthScopeCache getInstance() {
        if (instance == null) {
            synchronized (OauthScopeCache.class) {
                if (instance == null) {
                    instance = new OauthScopeCache();
                }
            }
        }
        return instance;
    }

    /**
     * Add a cache entry.
     *
     * @param key   Key which cache entry is indexed.
     * @param entry Actual object where cache entry is placed.
     */
    public void addToCache(String key, Scope entry) {
        super.addToCache(key, entry);
    }

    /**
     * Retrieves a cache entry.
     *
     * @param key CacheKey
     * @return Cached entry.
     */
    public Scope getValueFromCache(String key) {
        Scope entry = super.getValueFromCache(key);
        return entry;
    }

    /**
     * Clears a cache entry.
     *
     * @param key Key to clear cache.
     */
    public void clearCacheEntry(String key) {
        super.clearCacheEntry(key);
    }
}
