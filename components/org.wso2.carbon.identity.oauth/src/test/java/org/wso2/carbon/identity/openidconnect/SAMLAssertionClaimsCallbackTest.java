/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
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
package org.wso2.carbon.identity.openidconnect;

import com.nimbusds.jwt.JWTClaimsSet;
import org.mockito.Mock;
import org.mockito.Spy;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.XMLObject;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import static org.mockito.Mockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertTrue;

/**
 * Class which tests SAMLAssertionClaimsCallback.
 */

public class SAMLAssertionClaimsCallbackTest extends PowerMockTestCase {

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    @Spy
    SAMLAssertionClaimsCallback samlAssertionClaimsCallback;

    OAuthComponentServiceHolder oAuthComponentServiceHolder;

    @Mock
    OAuthTokenReqMessageContext requestMsgCtx;

    @Mock
    private UserRealm userRealm;

    @Mock
    private UserStoreManager userStoreManager;

    @Mock
    private RealmConfiguration realmConfiguration;

    @Mock
    private JWTClaimsSet jwtClaimsSet;

    @Mock
    private RealmService realmService;

    @Mock
    XMLObject xmlObject;

    @BeforeTest
    public void setUp() throws Exception {
        oAuthComponentServiceHolder = OAuthComponentServiceHolder.getInstance();
        realmService = mock(RealmService.class);
        oAuthComponentServiceHolder.setRealmService(realmService);
        userRealm = mock(UserRealm.class);
        when(realmService.getTenantUserRealm(MultitenantConstants.SUPER_TENANT_ID)).thenReturn(userRealm);
        userStoreManager = mock(UserStoreManager.class);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        realmConfiguration = mock(RealmConfiguration.class);
        when(userStoreManager.getRealmConfiguration()).thenReturn(realmConfiguration);
        when(realmConfiguration.getUserStoreProperty(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR)).
                thenReturn(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR_DEFAULT);

        samlAssertionClaimsCallback = new SAMLAssertionClaimsCallback();
    }

    @Test
    public void testHandleCustomClaims() throws Exception {
        jwtClaimsSet = mock(JWTClaimsSet.class);
        requestMsgCtx = mock(OAuthTokenReqMessageContext.class);
        Assertion assertion = mock(Assertion.class);
        when(requestMsgCtx.getProperty(OAuthConstants.OAUTH_SAML2_ASSERTION)).thenReturn(assertion);
        samlAssertionClaimsCallback.handleCustomClaims(jwtClaimsSet, requestMsgCtx);
        assertTrue(jwtClaimsSet.getAllClaims().isEmpty());
    }
}
