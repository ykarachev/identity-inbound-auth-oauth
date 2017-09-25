/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.util;

import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthConsumerDAO;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.model.ClientCredentialDO;

import static org.mockito.Matchers.*;
import static org.powermock.api.mockito.PowerMockito.*;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

@PrepareForTest({OAuthServerConfiguration.class, OAuthCache.class})
public class OAuth2UtilTest {

    String scopeArr[] = new String[]{"scope1", "scope2", "scope3"};
    String scopeStr = "scope1 scope2 scope3";
    String clientId = "IbWwXLf5MnKSY6x6gnR_7gd7f1wa";
    String clientSecret = "5_EekLmABh_cPdmmYxCTwRdyDH4a";

    @DataProvider(name = "BuildScopeString")
    public Object[][] buildScopeString() {
        return new Object[][] {{scopeArr, scopeStr}, {null, null}, {new String[0], ""}};
    }

    @Test(dataProvider = "BuildScopeString")
    public void testBuildScopeString(String arr[], String response) throws Exception {

        OAuthServerConfiguration mock = mock(OAuthServerConfiguration.class);
        when(mock.getTimeStampSkewInSeconds()).thenReturn(3600L);

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mock);

        Assert.assertEquals(OAuth2Util.buildScopeString(arr), response);
    }

    @DataProvider(name = "BuildScopeArray")
    public Object[][] buildScopeArray() {
        return new Object[][] {{scopeStr, scopeArr}, {null, new String[0]}};
    }

    @Test(dataProvider = "BuildScopeArray")
    public void testBuildScopeArray(String scopes, String response[]) throws Exception {

        OAuthServerConfiguration mock = mock(OAuthServerConfiguration.class);
        when(mock.getTimeStampSkewInSeconds()).thenReturn(3600L);

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mock);

        Assert.assertEquals(OAuth2Util.buildScopeArray(scopes), response);
    }

    @Test
    public void testAuthenticateClientCacheHit() throws Exception {

        OAuthServerConfiguration mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        when(mockOAuthServerConfiguration.getTimeStampSkewInSeconds()).thenReturn(3600L);

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockOAuthServerConfiguration);

        OAuthCache mockOAuthCache = mock(OAuthCache.class);
        ClientCredentialDO mockCacheEntry = mock(ClientCredentialDO.class);
        when(mockCacheEntry.getClientSecret()).thenReturn(clientSecret);

        when(mockOAuthCache.getValueFromCache(any(OAuthCacheKey.class))).thenReturn(mockCacheEntry);

        mockStatic(OAuthCache.class);
        when(OAuthCache.getInstance()).thenReturn(mockOAuthCache);

        Assert.assertTrue(OAuth2Util.authenticateClient(clientId, clientSecret));
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }
}
