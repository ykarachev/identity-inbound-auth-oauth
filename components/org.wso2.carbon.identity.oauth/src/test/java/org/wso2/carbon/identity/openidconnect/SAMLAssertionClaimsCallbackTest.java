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
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.xml.XMLObject;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.w3c.dom.Element;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.registry.core.session.UserRegistry;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.ArrayList;
import java.util.List;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertTrue;

/**
 * Class which tests SAMLAssertionClaimsCallback.
 */
@PrepareForTest({
        AuthorizationGrantCache.class,
        PrivilegedCarbonContext.class,
        IdentityTenantUtil.class,
        OAuth2ServiceComponentHolder.class
})
public class SAMLAssertionClaimsCallbackTest {

    private String SAMPLE_ACCESS_TOKEN = "4952b467-86b2-31df-b63c-0bf25cec4f86";
    private int SAMPLE_TENANT_ID = 1234;

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    @Spy
    SAMLAssertionClaimsCallback samlAssertionClaimsCallback;

    OAuthComponentServiceHolder oAuthComponentServiceHolder;

    @Spy
    AuthorizationGrantCache authorizationGrantCache;

    @Mock
    OAuthTokenReqMessageContext requestMsgCtx;

    @Mock
    OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext;

    @Spy
    PrivilegedCarbonContext context;

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

    @Test
    public void testCustomClaimForOAuthTokenReqMessageContext() throws Exception {
        jwtClaimsSet = mock(JWTClaimsSet.class);
        requestMsgCtx = mock(OAuthTokenReqMessageContext.class);
        Assertion assertion = mock(Assertion.class);

        AttributeStatement statement = mock(AttributeStatement.class);
        List<AttributeStatement> attributeStatementList = new ArrayList<>();
        attributeStatementList.add(statement);
        when(assertion.getAttributeStatements()).thenReturn(attributeStatementList);

        List<Attribute> attributesList = new ArrayList<>();
        Attribute attribute = mock(Attribute.class);
        attributesList.add(attribute);
        when(statement.getAttributes()).thenReturn(attributesList);

        List<XMLObject> values = new ArrayList<>();
        XMLObject obj = mock(XMLObject.class);
        values.add(obj);

        Element ele = mock(Element.class);
        when(attribute.getAttributeValues()).thenReturn(values);
        when(values.get(0).getDOM()).thenReturn(ele);
        when(requestMsgCtx.getProperty(OAuthConstants.OAUTH_SAML2_ASSERTION)).thenReturn(assertion);
        samlAssertionClaimsCallback.handleCustomClaims(jwtClaimsSet, requestMsgCtx);
        assertTrue(jwtClaimsSet.getAllClaims().isEmpty());
    }

    @Test
    public void testHandleClaimsForOAuthAuthzReqMessageContext() throws Exception {
        jwtClaimsSet = mock(JWTClaimsSet.class);
        oAuthAuthzReqMessageContext = mock(OAuthAuthzReqMessageContext.class);
        String[] approvedScopes = {"openid", "testScope1", "testScope2"};
        when(oAuthAuthzReqMessageContext.getApprovedScope()).thenReturn(approvedScopes);
        when(oAuthAuthzReqMessageContext.getProperty(OAuthConstants.ACCESS_TOKEN))
                .thenReturn(SAMPLE_ACCESS_TOKEN);
        mockStatic(AuthorizationGrantCache.class);
        authorizationGrantCache = mock(AuthorizationGrantCache.class);
        AuthorizationGrantCacheEntry authorizationGrantCacheEntry = mock(AuthorizationGrantCacheEntry.class);
        when(AuthorizationGrantCache.getInstance()).thenReturn(authorizationGrantCache);
        when(authorizationGrantCache.getValueFromCache(any(AuthorizationGrantCacheKey.class))).
                thenReturn(authorizationGrantCacheEntry);
        OAuth2AuthorizeReqDTO oAuth2AuthorizeReqDTO = mock(OAuth2AuthorizeReqDTO.class);
        when(oAuthAuthzReqMessageContext.getAuthorizationReqDTO()).thenReturn(oAuth2AuthorizeReqDTO);
        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        when(oAuth2AuthorizeReqDTO.getUser()).thenReturn(authenticatedUser);
        when(authenticatedUser.isFederatedUser()).thenReturn(true);

        mockStatic(PrivilegedCarbonContext.class);
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(SAMPLE_TENANT_ID);

        context = mock(PrivilegedCarbonContext.class);
        when(PrivilegedCarbonContext.getThreadLocalCarbonContext()).thenReturn(context);

        RegistryService registry = mock(RegistryService.class);
        mockStatic(OAuth2ServiceComponentHolder.class);
        when(OAuth2ServiceComponentHolder.getRegistryService()).thenReturn(registry);

        UserRegistry userRegistry = mock(UserRegistry.class);
        when(registry.getConfigSystemRegistry(SAMPLE_TENANT_ID)).thenReturn(userRegistry);

        Resource resource = mock(Resource.class);
        when(userRegistry.get(OAuthConstants.SCOPE_RESOURCE_PATH)).thenReturn(resource);

        samlAssertionClaimsCallback.handleCustomClaims(jwtClaimsSet, oAuthAuthzReqMessageContext);

    }
}
