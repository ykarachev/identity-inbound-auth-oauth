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

import org.apache.commons.lang.StringUtils;
import org.mockito.Mock;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.dao.TestOAuthDAOBase;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.nio.file.Paths;

public class AuthorizationHandlerManagerTest extends TestOAuthDAOBase {

    private AuthorizationHandlerManager authorizationHandlerManager;
    private OAuth2AuthorizeReqDTO authzReqDTO = new OAuth2AuthorizeReqDTO();
    private static final String carbonHome =
            new AuthorizationHandlerManagerTest().getClass().getResource("/").getFile();
    private static final String DB_NAME = "jdbc/WSO2IdentityDB";
    private static final String CLIENT_ID = "ca19a540f544777860e44e75f605d927";
    private static final String SECRET = "87n9a540f544777860e44e75f605d435";
    private static final String APP_NAME = "myApp";
    private static final String USER_NAME = "user1";
    private static final String APP_STATE = "ACTIVE";
    private static final String CALLBACK = "http://localhost:8080/redirect";
    private static final String ACC_TOKEN = "fakeAccToken";
    private static final String ACC_TOKEN_SECRET = "fakeTokenSecret";
    private static final String REQ_TOKEN = "fakeReqToken";
    private static final String REQ_TOKEN_SECRET = "fakeReqToken";
    private static final String SCOPE = "openid";
    private static final String AUTHZ_USER = "fakeAuthzUser";
    private static final String OAUTH_VERIFIER = "fakeOauthVerifier";
    private static final String NEW_SECRET = "a459a540f544777860e44e75f605d875";

    @Mock
    private RealmService realmService;

    @Mock
    private TenantManager tenantManager;

    @BeforeTest
    public void setUp() throws Exception {

    }

    @Test
    public void testHandleAuthorizationIDTokenTokenResponseTypeCacheMiss() throws Exception {

    }

    public static String getFilePath(String fileName) {
        if (StringUtils.isNotBlank(fileName)) {
            return Paths.get(carbonHome, TestConstants.DB_SCRIPTS_FOLDER_NAME, fileName)
                        .toString();
        }
        throw new IllegalArgumentException("DB Script file name cannot be empty.");
    }

}
