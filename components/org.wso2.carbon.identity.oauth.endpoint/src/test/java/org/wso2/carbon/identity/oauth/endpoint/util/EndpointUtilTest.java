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
package org.wso2.carbon.identity.oauth.endpoint.util;

import org.apache.axiom.util.base64.Base64Utils;
import org.apache.commons.collections.map.HashedMap;
import org.apache.commons.logging.Log;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationRequestCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.SessionDataCache;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheEntry;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheKey;
import org.wso2.carbon.identity.oauth.common.exception.OAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doAnswer;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

@PrepareForTest ( {SessionDataCache.class, OAuthServerConfiguration.class, OAuth2Util.class, IdentityUtil.class,
        FrameworkUtils.class})
public class EndpointUtilTest extends PowerMockTestCase {

    @Mock
    Log mockedLog;

    @Mock
    SessionDataCache mockedSessionDataCache;

    @Mock
    SessionDataCacheEntry mockedSessionDataCacheEntry;

    @Mock
    OAuthServerConfiguration mockedOAuthServerConfiguration;

    @Mock
    OAuth2Util.OAuthURL mockedOAuthUrl;

    private static final String COMMONAUTH_URL = "https://localhost:9443/commonauth";
    private static final String OIDC_CONSENT_PAGE_URL =
            "https://localhost:9443/authenticationendpoint/oauth2_consent.do";
    private static final String OAUTH2_CONSENT_PAGE_URL =
            "https://localhost:9443/authenticationendpoint/oauth2_authz.do";

    private String username;
    private String password;
    private String sessionDataKey;
    private String clientId;

    @BeforeTest
    public void setUp() {

        username = "myUsername";
        password = "myPassword";
        sessionDataKey = "1234567890";
        clientId = "myClientId";
    }

    @DataProvider(name = "provideAuthzHeader")
    public Object[][] provideAuthzHeader() {

        String authzValue = "Basic " + Base64Utils.encode((username + ":" + password).getBytes());

        return new Object[][] {
                { authzValue, username, null},
                { username, null, "Error decoding authorization header"},
                { "Basic " + Base64Utils.encode(username.getBytes()), null, "Error decoding authorization header"},
                { null, null, "Authorization header value is null"},
        };
    }

    @Test (dataProvider = "provideAuthzHeader")
    public void testExtractCredentialsFromAuthzHeader(String header, String expected, String msg) {

        String[] credentials = null;
        try {
            credentials = EndpointUtil.extractCredentialsFromAuthzHeader(header);
            Assert.assertEquals(credentials[0], expected, "Invalid credentials returned");
        } catch (OAuthClientException e) {
            Assert.assertTrue(e.getMessage().contains(msg), "Unexpected Exception");
        }

    }

    @DataProvider(name = "provideDataForUserConsentURL")
    public Object[][] provideDataForUserConsentURL() {

        OAuth2Parameters params = new OAuth2Parameters();
        params.setApplicationName("TestApplication");
        params.setScopes(new HashSet<String>(Arrays.asList("scope1", "scope2")));

        return new Object[][] {
                { params, true, true, false, "QueryString", true},
                { null, true, true, false, "QueryString", true},
                { params, false, true, false, "QueryString", true},
                { params, true, false, false, "QueryString", true},
                { params, true, false, false, "QueryString", false},
                { params, true, true, false, null, true},
                { params, true, true, true, "QueryString", true},
        };
    }

    @Test(dataProvider = "provideDataForUserConsentURL")
    public void testGetUserConsentURL(Object oAuth2ParamObject, boolean isOIDC, boolean cacheEntryExists,
                                      boolean throwError, String queryString, boolean isDebugEnabled) throws Exception {

        setMockedLog(isDebugEnabled);
        OAuth2Parameters parameters = (OAuth2Parameters) oAuth2ParamObject;

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);

        mockStatic(OAuth2Util.class);
        mockStatic(OAuth2Util.OAuthURL.class);
        when(OAuth2Util.OAuthURL.getOIDCConsentPageUrl()).thenReturn(OIDC_CONSENT_PAGE_URL);
        when(OAuth2Util.OAuthURL.getOAuth2ConsentPageUrl()).thenReturn(OAUTH2_CONSENT_PAGE_URL);

        mockStatic(SessionDataCache.class);
        when(SessionDataCache.getInstance()).thenReturn(mockedSessionDataCache);
        if (cacheEntryExists) {
            when(mockedSessionDataCache.getValueFromCache(any(SessionDataCacheKey.class))).
                    thenReturn(mockedSessionDataCacheEntry);
            when(mockedSessionDataCacheEntry.getQueryString()).thenReturn(queryString);
        } else {
            when(mockedSessionDataCache.getValueFromCache(any(SessionDataCacheKey.class))).
                    thenReturn(null);
        }

        String consentUrl;
        try {
            consentUrl = EndpointUtil.getUserConsentURL(parameters, username, sessionDataKey, isOIDC);
            if (isOIDC) {
                Assert.assertTrue(consentUrl.contains(OIDC_CONSENT_PAGE_URL), "Incorrect consent page url for OIDC");
            } else {
                Assert.assertTrue(consentUrl.contains(OAUTH2_CONSENT_PAGE_URL), "Incorrect consent page url for OAuth");
            }

            Assert.assertTrue(consentUrl.contains(URLEncoder.encode(username, "UTF-8")),
                    "loggedInUser parameter value is not found in url");
            Assert.assertTrue(consentUrl.contains(URLEncoder.encode("TestApplication", "ISO-8859-1")),
                    "application parameter value is not found in url");
            Assert.assertTrue(consentUrl.contains("scope1+scope2"), "scope parameter value is not found in url");
            if (queryString != null && cacheEntryExists) {
                Assert.assertTrue(consentUrl.contains(queryString), "spQueryParams value is not found in url");
            }

        } catch (OAuthSystemException e) {
            Assert.assertTrue(e.getMessage().contains("Error while retrieving the application name"));
        }

    }

    @DataProvider (name = "provideScopeData")
    public Object[][] provideScopeData() {

        return new Object[][] {
                { null, "oauth2"},
                { new HashSet<String>() {{ add("scope1");}}, "oauth2"},
                { new HashSet<String>() {{ add("openid");}}, "oidc"},
        };
    }

    @Test (dataProvider = "provideScopeData")
    public void testGetLoginPageURL(Set<String> scopes, String queryParam) throws Exception {

        Map<String, String[]> reqParams = new HashedMap();
        reqParams.put("param1", new String[]{"value1"});

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);

        mockStatic(OAuth2Util.class);
        when(OAuth2Util.getClientTenatId()).thenReturn(-1234);

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean())).thenReturn(COMMONAUTH_URL);

        mockStatic(FrameworkUtils.class);
        doAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                return null;
            }
        }).when(FrameworkUtils.class, "addAuthenticationRequestToCache", anyString(),
                any(AuthenticationRequestCacheEntry.class));

        String url = EndpointUtil.getLoginPageURL(clientId, sessionDataKey, true, true, scopes, reqParams);
        Assert.assertTrue(url.contains("type=" + queryParam), "type parameter is not set according to the scope");
    }

    private void setMockedLog(boolean isDebugEnabled) throws Exception {

        Constructor<EndpointUtil> constructor = EndpointUtil.class.getDeclaredConstructor(new Class[0]);
        constructor.setAccessible(true);
        Object claimUtilObject = constructor.newInstance(new Object[0]);
        Field logField = claimUtilObject.getClass().getDeclaredField("log");

        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(logField, logField.getModifiers() & ~Modifier.FINAL);

        logField.setAccessible(true);
        logField.set(claimUtilObject, mockedLog);
        when(mockedLog.isDebugEnabled()).thenReturn(isDebugEnabled);
    }
}
