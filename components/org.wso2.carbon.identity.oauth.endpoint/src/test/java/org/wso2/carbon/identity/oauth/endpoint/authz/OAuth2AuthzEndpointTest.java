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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.endpoint.authz;

import org.apache.commons.collections.map.HashedMap;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.RequestCoordinator;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.cache.SessionDataCache;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheEntry;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheKey;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth.endpoint.util.TestOAthEndpointBase;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import static org.mockito.Matchers.anyString;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.doAnswer;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.AssertJUnit.assertTrue;

@PrepareForTest({ OAuth2Util.class, SessionDataCache.class, OAuthServerConfiguration.class, IdentityDatabaseUtil.class,
        EndpointUtil.class, FrameworkUtils.class})
public class OAuth2AuthzEndpointTest extends TestOAthEndpointBase {

    @Mock
    HttpServletRequest httpServletRequest;

    @Mock
    HttpServletResponse httpServletResponse;

    @Mock
    SessionDataCache sessionDataCache;

    @Mock
    SessionDataCacheEntry loginCacheEntry, consentCacheEntry;

    @Mock
    OAuthServerConfiguration oAuthServerConfiguration;

    @Mock
    TokenPersistenceProcessor tokenPersistenceProcessor;

    @Mock
    OAuth2Service oAuth2Service;

    @Mock
    HttpSession httpSession;

    @Mock
    RequestCoordinator requestCoordinator;

    private static final String ERROR_PAGE_URL = "https://localhost:9443/authenticationendpoint/oauth2_error.do";

    private OAuth2AuthzEndpoint oAuth2AuthzEndpoint;
    private String clientId;
    private String sessionDataKeyConsent;
    private String sessionDataKey;
    private String secret;
    private String appName;
    private String username;
    private String inactiveClientId;
    private String inactiveAppName;

    @BeforeTest
    public void setUp() throws Exception {
        Path path = Paths.get("src", "test", "resources", "carbon_home");
        System.setProperty(CarbonBaseConstants.CARBON_HOME, path.toString());

        oAuth2AuthzEndpoint = new OAuth2AuthzEndpoint();
        sessionDataKeyConsent = "savedSessionDataKeyForConsent";
        sessionDataKey = "savedSessionDataKey";
        clientId = "ca19a540f544777860e44e75f605d927";
        secret = "87n9a540f544777860e44e75f605d435";
        appName = "myApp";
        inactiveClientId = "inactiveId";
        secret = "87n9a540f544777860e44e75f605d435";
        inactiveAppName = "inactiveApp";
        username = "user1";

        initiateInMemoryH2();
        createOAuthApp(clientId, secret, username, appName, "ACTIVE");
        createOAuthApp(inactiveClientId, "dummySecret", username, inactiveAppName, "INACTIVE");
    }

    @AfterTest
    public void cleanData() throws Exception {
        super.cleanData();
    }

    @DataProvider(name = "providePostParams")
    public Object[][] providePostParams() {
        MultivaluedMap<String, String> paramMap1 = new MultivaluedHashMap<String, String>();
        List<String> list1 = new ArrayList<>();
        list1.add("value1");
        list1.add("value2");
        paramMap1.put("paramName1", list1);

        Map<String, String[]> requestParams1 = new HashedMap();
        requestParams1.put("reqParam1", new String[]{"val1", "val2"});

        MultivaluedMap<String, String> paramMap2 = new MultivaluedHashMap<String, String>();
        List<String> list2 = new ArrayList<>();
        list2.add("value1");
        paramMap2.put("paramName1", list2);

        Map<String, String[]> requestParams2 = new HashedMap();
        requestParams2.put("reqParam1", new String[]{"val1"});

        return new Object[][] {
                {paramMap2, requestParams2, 302},
                {paramMap1, requestParams2, 400},
        };
    }

    @Test (dataProvider = "providePostParams")
    public void testAuthorizePost(Object paramObject, Map<String, String[]> requestParams, int expected)
            throws Exception {
        MultivaluedMap<String, String> paramMap = (MultivaluedMap<String, String>) paramObject;
        when(httpServletRequest.getParameterMap()).thenReturn(requestParams);
        when(httpServletRequest.getParameterNames()).thenReturn(new Vector(requestParams.keySet()).elements());

        mockStatic(OAuth2Util.OAuthURL.class);
        when(OAuth2Util.OAuthURL.getOAuth2ErrorPageUrl()).thenReturn(ERROR_PAGE_URL);

        Response response = oAuth2AuthzEndpoint.authorizePost(httpServletRequest, httpServletResponse, paramMap);
        assertEquals(response.getStatus(), expected);
    }

    @DataProvider(name = "provideParams")
    public Object[][] provideParams() {
        initMocks(this);

        return new Object[][] {
                { AuthenticatorFlowStatus.SUCCESS_COMPLETED, new String[]{"val1", "val2"},
                        sessionDataKeyConsent, "true", "scope1", sessionDataKey, null, 400, "invalid_request" },
                { AuthenticatorFlowStatus.SUCCESS_COMPLETED, new String[]{clientId},
                        sessionDataKeyConsent, "true", "scope1", sessionDataKey, null, 302, "invalid_request" },
                { AuthenticatorFlowStatus.SUCCESS_COMPLETED, null,
                        null, "true", "scope1", null, null, 302, "invalid_request" },
                { AuthenticatorFlowStatus.SUCCESS_COMPLETED, new String[]{clientId},
                        sessionDataKeyConsent, "true", "scope1", "invalidSession", null, 302, "access_denied" },
                { AuthenticatorFlowStatus.SUCCESS_COMPLETED, new String[]{clientId},
                        "invalidConsentCacheKey", "true", "scope1", null, null, 302, "access_denied" },
                { AuthenticatorFlowStatus.SUCCESS_COMPLETED, new String[]{"invalidId"},
                        "invalidConsentCacheKey", "true", "scope1", sessionDataKey, null, 401, null },
                { AuthenticatorFlowStatus.SUCCESS_COMPLETED, new String[]{inactiveClientId},
                        "invalidConsentCacheKey", "true", "scope1", sessionDataKey, null, 401, null },
        };
    }

    @Test (dataProvider = "provideParams")
    public void testAuthorize(Object flowStatusObject, String[] clientId,
                              String sessionDataKayConsent, String toCommonAuth, String scope, String sessionDataKey,
                              Exception e, int expectedStatus, String expectedError) throws Exception {
        AuthenticatorFlowStatus flowStatus = (AuthenticatorFlowStatus) flowStatusObject;
        setMockHttpRequest(flowStatus, clientId, sessionDataKayConsent, toCommonAuth, scope, sessionDataKey);

        mockStatic(OAuth2Util.OAuthURL.class);
        when(OAuth2Util.OAuthURL.getOAuth2ErrorPageUrl()).thenReturn(ERROR_PAGE_URL);

        mockStatic(SessionDataCache.class);
        when(SessionDataCache.getInstance()).thenReturn(sessionDataCache);
        SessionDataCacheKey loginDataCacheKey = new SessionDataCacheKey(this.sessionDataKey);
        SessionDataCacheKey consentDataCacheKey = new SessionDataCacheKey(this.sessionDataKeyConsent);
        when(sessionDataCache.getValueFromCache(loginDataCacheKey)).thenReturn(loginCacheEntry);
        when(sessionDataCache.getValueFromCache(consentDataCacheKey)).thenReturn(consentCacheEntry);

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(oAuthServerConfiguration.getPersistenceProcessor()).thenReturn(tokenPersistenceProcessor);
        when(tokenPersistenceProcessor.getProcessedClientId(anyString())).thenAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                return (String) invocation.getArguments()[0];
            }
        });

        mockStatic(IdentityDatabaseUtil.class);
        if (e != null && e instanceof SQLException) {
            connection.commit();
        }
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

        Response response = oAuth2AuthzEndpoint.authorize(httpServletRequest, httpServletResponse);
        assertEquals(response.getStatus(), expectedStatus);

        MultivaluedMap<String, Object> responseMetadata = response.getMetadata();

        if (expectedError != null) {
            String location = (String) responseMetadata.get("Location").get(0);
            assertTrue(location.contains(expectedError));
        }
    }

    private void setMockHttpRequest(AuthenticatorFlowStatus flowStatus, String[] clientId, String sessionDataKayConsent,
                                    String toCommonAuth, String scope, String sessionDataKey) {
        final Map<String, String[]> requestParams = new HashedMap();
        if (clientId != null) {
            requestParams.put("client_id", clientId);
        }
        requestParams.put("sessionDataKeyConsent", new String[]{sessionDataKayConsent});
        requestParams.put("tocommonauth", new String[]{toCommonAuth});
        requestParams.put("scope", new String[]{scope});

        final Map<String, Object> requestAttributes = new HashedMap();
        requestAttributes.put("authenticatorFlowStatus", flowStatus);
        requestAttributes.put("sessionDataKey", sessionDataKey);

        doAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                String key = (String) invocation.getArguments()[0];
                String value = requestParams.get(key) != null ? requestParams.get(key)[0]: null ;
                return value;
            }
        }).when(httpServletRequest).getParameter(anyString());

        doAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                String key = (String) invocation.getArguments()[0];
                return requestAttributes.get(key);
            }
        }).when(httpServletRequest).getAttribute(anyString());

        when(httpServletRequest.getParameterMap()).thenReturn(requestParams);
        when(httpServletRequest.getSession()).thenReturn(httpSession);
    }
}
