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

package org.wso2.carbon.identity.oauth.endpoint.user.impl;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * Test class to test UserInfoJWTResponse.
 */
@PrepareForTest({AuthorizationGrantCache.class})
public class UserInfoJWTResponseTest extends UserInfoResponseBaseTest {

    private UserInfoJWTResponse userInfoJWTResponse;

    @BeforeClass
    public void setup() {
        userInfoJWTResponse = new UserInfoJWTResponse();
    }

    @DataProvider(name = "subjectClaimDataProvider")
    public Object[][] provideSubjectData() {
        return getSubjectClaimTestData();
    }

    @Test(dataProvider = "subjectClaimDataProvider")
    public void testSubjectClaim(Map<String, Object> inputClaims,
                                 boolean appendTenantDomain,
                                 boolean appendUserStoreDomain,
                                 String expectedSubjectValue) throws Exception {
        try {
            prepareForSubjectClaimTest(inputClaims, appendTenantDomain, appendUserStoreDomain);
            String responseString =
                    userInfoJWTResponse.getResponseString(getTokenResponseDTO(AUTHORIZED_USER_FULL_QUALIFIED));

            JWT jwt = JWTParser.parse(responseString);
            assertNotNull(jwt);
            assertNotNull(jwt.getJWTClaimsSet());
            assertNotNull(jwt.getJWTClaimsSet().getSubject());
            assertEquals(jwt.getJWTClaimsSet().getSubject(), expectedSubjectValue);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    @Test
    public void testEssentialClaims() throws Exception {

        final Map<String, Object> inputClaims = new HashMap<>();
        inputClaims.put(FIRST_NAME, FIRST_NAME_VALUE);
        inputClaims.put(LAST_NAME, LAST_NAME_VALUE);
        inputClaims.put(EMAIL, EMAIL_VALUE);

        final Map<String, List<String>> oidcScopeMap = new HashMap<>();
        oidcScopeMap.put(OIDC_SCOPE, Collections.singletonList(FIRST_NAME));

        List<String> essentialClaims = Collections.singletonList(EMAIL);
        prepareForResponseClaimTest(inputClaims, oidcScopeMap, false);

        // Mock for essential claims.
        when(OAuth2Util.getEssentialClaims(anyString(), anyString())).thenReturn(essentialClaims);
        when(authorizationGrantCacheEntry.getEssentialClaims()).thenReturn("ESSENTIAL_CLAIM_JSON");

        String responseString =
                userInfoJWTResponse.getResponseString(getTokenResponseDTO(AUTHORIZED_USER_FULL_QUALIFIED));

        JWT jwt = JWTParser.parse(responseString);
        assertNotNull(jwt.getJWTClaimsSet());

        ReadOnlyJWTClaimsSet jwtClaimsSet = jwt.getJWTClaimsSet();
        assertNotNull(jwtClaimsSet);
        assertNotNull(jwtClaimsSet.getSubject());

        // Assert that claims not in scope were not sent
        assertNull(jwtClaimsSet.getClaim(LAST_NAME));

        // Assert claim in scope was sent
        assertNotNull(jwtClaimsSet.getClaim(FIRST_NAME));
        assertEquals(jwtClaimsSet.getClaim(FIRST_NAME), FIRST_NAME_VALUE);

        // Assert whether essential claims are available even though they were not in requested scope.
        assertNotNull(jwtClaimsSet.getClaim(EMAIL));
        assertEquals(jwtClaimsSet.getClaim(EMAIL), EMAIL_VALUE);
    }

    @DataProvider(name = "responseStringInputs")
    public Object[][] responseStringInputs() {
        return getOidcScopeFilterTestData();
    }

    @Test(dataProvider = "responseStringInputs")
    public void testGetResponseString(Map<String, Object> inputClaims,
                                      Map<String, List<String>> oidcScopeMap,
                                      boolean getClaimsFromCache,
                                      String[] requestedScopes,
                                      Map<String, Object> expectedClaims) throws Exception {
        try {
            prepareForResponseClaimTest(inputClaims, oidcScopeMap, getClaimsFromCache);
            String responseString =
                    userInfoJWTResponse.getResponseString(
                            getTokenResponseDTO(AUTHORIZED_USER_FULL_QUALIFIED, requestedScopes));

            JWT jwt = JWTParser.parse(responseString);
            ReadOnlyJWTClaimsSet jwtClaimsSet = jwt.getJWTClaimsSet();
            assertNotNull(jwtClaimsSet);
            assertNotNull(jwtClaimsSet.getSubject());

            for (Map.Entry<String, Object> expectedClaimEntry : expectedClaims.entrySet()) {
                assertTrue(jwtClaimsSet.getAllClaims().containsKey(expectedClaimEntry.getKey()));
                assertNotNull(jwtClaimsSet.getClaim(expectedClaimEntry.getKey()));
                assertEquals(
                        expectedClaimEntry.getValue(),
                        jwtClaimsSet.getClaim(expectedClaimEntry.getKey())
                );
            }
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }
}
