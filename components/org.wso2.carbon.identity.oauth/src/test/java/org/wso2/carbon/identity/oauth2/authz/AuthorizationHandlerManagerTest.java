/*
* Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package org.wso2.carbon.identity.oauth2.authz;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.test.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.test.common.testng.WithH2Database;
import org.wso2.carbon.identity.test.common.testng.WithRealmService;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

@WithCarbonHome
@WithH2Database(jndiName = "jdbc/WSO2IdentityDB", files = { "dbScripts/h2_with_application_and_token.sql" })
@WithRealmService(tenantId = TestConstants.TENANT_ID, tenantDomain = TestConstants.TENANT_DOMAIN,
        initUserStoreManager = true)
public class AuthorizationHandlerManagerTest extends PowerMockIdentityBaseTest {

    private AuthorizationHandlerManager authorizationHandlerManager;
    private OAuth2AuthorizeReqDTO authzReqDTO = new OAuth2AuthorizeReqDTO();


    @BeforeClass
    public void setUp() throws Exception {
        authorizationHandlerManager = AuthorizationHandlerManager.getInstance();
    }

    @Test
    public void testHandleAuthorizationIDTokenTokenResponseTypeCacheMiss() throws Exception {
        authzReqDTO.setResponseType(TestConstants.AUTHORIZATION_HANDLER_RESPONSE_TYPE_ID_TOKEN_TOKEN);
        authzReqDTO.setConsumerKey(TestConstants.CLIENT_ID);
        authzReqDTO.setScopes(TestConstants.SCOPE_STRING.split(" "));
        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName(TestConstants.USER_NAME);
        user.setTenantDomain(TestConstants.TENANT_DOMAIN);
        user.setUserStoreDomain(TestConstants.USER_DOMAIN_PRIMARY);
        authzReqDTO.setUser(user);
        OAuth2AuthorizeRespDTO respDTO = authorizationHandlerManager.handleAuthorization(authzReqDTO);
    }

}