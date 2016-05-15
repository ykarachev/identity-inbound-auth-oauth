/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2new.listener;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.listener.AbstractCacheListener;
import org.wso2.carbon.identity.oauth2new.model.AccessToken;

import javax.cache.event.CacheEntryEvent;
import javax.cache.event.CacheEntryListenerException;
import javax.cache.event.CacheEntryRemovedListener;

/*
 * Since OAuth2 access tokens are persisted asynchronously, there is a possibility that even if the DB persistence of
 * the new access token fails, still the new access token may be served from cache. However the access token validation
 * may fail since it uses a different cache and that cache may not contain the same access token,
 * or it looks into the DB and finds no valid access token. To avoid this what we do here whenever one of the cache
 * entries in either cache gets removed we forcefully remove the access token from the other cache too.
 *
 */
public class OAuth2CacheListener extends AbstractCacheListener<String, AccessToken>
        implements CacheEntryRemovedListener<String, AccessToken> {

    private static Log log = LogFactory.getLog(OAuth2CacheListener.class);

    @Override
    public void entryRemoved(CacheEntryEvent<? extends String, ? extends AccessToken> cacheEntryEvent)
            throws CacheEntryListenerException {

    }
}
