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

package org.wso2.carbon.identity.oauth2.dao;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.SQLQueries;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.util.DAOUtils;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;

import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertNotNull;

/**
 * Unit tests for TokenMgtDAO.
 */
@PrepareForTest({IdentityDatabaseUtil.class, IdentityUtil.class, OAuthServerConfiguration.class})
public class TokenMgtDAOTest {

    private static final String DB_NAME = "TOKEN_DB";

    private static final String OAUTH_TOKEN_PERSISTENCE_POOL_SIZE = "OAuth.TokenPersistence.PoolSize";

    private static final String FRAMEWORK_PERSISTENCE_POOL_SIZE = "JDBCPersistenceManager.SessionDataPersist.PoolSize";

    private static final String OAUTH_TOKEN_PERSISTENCE_RETRY_COUNT = "OAuth.TokenPersistence.RetryCount";

    private static final String CONSUMER_KEY_1 = "EdtLUfz6XbOv7sqlZEo_ccgt7y4a";

    private static final String CONSUMER_KEY_2 = "_hp9Py_qE5U2mpjSVt5OF5u2SCwa";

    private static final String CONSUMER_SECRET_1 = "Bhj89LUfz6XbOv7sqlZEo_c8gt7y4a";

    private static final String CONSUMER_SECRET_2 = "_ll8kky_qE5U2mpjSVt5OF5u2SCwa";

    private static final String CALLBACK_URL = "http://localhost:8080/sample/oauth2client";

    private static final String AUTHZ_CODE_1 = "K858ffs6XbOv7sqlZEo_cc4gt7y4a";

    private static final String AUTHZ_CODE_2 = "O778jfs6XbOv7sqlZEo_cc4gt7y4a";

    private static final String AUTHZ_CODE_ID_1 = "ff89fs6XbOv7sqlZEo_cc4gt7y4a";

    private static final String AUTHZ_CODE_ID_2 = "oo7ff9fs6XbOv7sqlZEo_cc4gt7y4a";

    private static final String SAMPLE_TENANT_DOMAIN = "wso2.com";

    private static final int SAMPLE_TENANT_ID = 1;

    private TokenMgtDAO tokenMgtDAO;

    @Mock
    private OAuthServerConfiguration mockedOAuthServerConfiguration;

    @Mock
    private RealmService mockedRealmService;

    @Mock
    private TenantManager mockedTenantManager;

    @BeforeClass
    public void initTest() throws Exception {
        DAOUtils.initializeDataSource(DB_NAME, DAOUtils.getFilePath("token.sql"));
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getProperty(OAUTH_TOKEN_PERSISTENCE_POOL_SIZE)).thenReturn("0");
        when(IdentityUtil.getProperty(FRAMEWORK_PERSISTENCE_POOL_SIZE)).thenReturn("0");
        when(IdentityUtil.getProperty(OAUTH_TOKEN_PERSISTENCE_RETRY_COUNT)).thenReturn(null);

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        tokenMgtDAO = new TokenMgtDAO();

        createApplication(CONSUMER_KEY_1, CONSUMER_SECRET_1, MultitenantConstants.SUPER_TENANT_ID);
        createApplication(CONSUMER_KEY_2, CONSUMER_SECRET_2, SAMPLE_TENANT_ID);

        OAuthComponentServiceHolder.getInstance().setRealmService(mockedRealmService);
        when(mockedRealmService.getTenantManager()).thenReturn(mockedTenantManager);
        when(mockedTenantManager.getTenantId(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)).thenReturn
                (MultitenantConstants.SUPER_TENANT_ID);
        when(mockedTenantManager.getTenantId(SAMPLE_TENANT_DOMAIN)).thenReturn(SAMPLE_TENANT_ID);
    }

    @DataProvider(name = "storeAuthorizationCodeDataProvider")
    public Object[][] storeAuthorizationCodeData() {

        return new Object[][]{
                {
                        CONSUMER_KEY_1,
                        AUTHZ_CODE_ID_1,
                        AUTHZ_CODE_1,
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME
                },
        };
    }

    @Test(dataProvider = "storeAuthorizationCodeDataProvider")
    public void storeAuthorizationCode(String consumerKey, String authzCodeId, String authzCode, String callbackUrl,
                                       String tenantDomain) throws IdentityOAuth2Exception, SQLException {
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("sampleUser");
        authenticatedUser.setTenantDomain(tenantDomain);
        authenticatedUser.setUserStoreDomain(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);

        AuthzCodeDO authzCodeDO = new AuthzCodeDO(authenticatedUser, new String[]{"scope1", "scope2"},
                new Timestamp(System.currentTimeMillis()), 3600L, callbackUrl, consumerKey, authzCode, authzCodeId,
                null, null);
        mockStatic(IdentityDatabaseUtil.class);
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            tokenMgtDAO.storeAuthorizationCode(authzCode, consumerKey, callbackUrl, authzCodeDO);
            assertNotNull(tokenMgtDAO.getAuthzCodeByCodeId(authzCodeId), "Failed to persist authorize code.");
        }
    }

    private void createApplication(String consumerKey, String consumerSecret, int tenantId)
            throws SQLException {
        try (Connection connection = DAOUtils.getConnection(DB_NAME);
             PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.ADD_OAUTH_APP);) {
            prepStmt.setString(1, consumerKey);
            prepStmt.setString(2, consumerSecret);
            prepStmt.setString(3, "testUser");
            prepStmt.setInt(4, tenantId);
            prepStmt.setString(5, UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
            prepStmt.setString(6, "oauth2-app");
            prepStmt.setString(7, "OAuth-2.0");
            prepStmt.setString(8, CALLBACK_URL);
            prepStmt.setString(9, "refresh_token urn:ietf:params:oauth:grant-type:saml2-bearer implicit password " +
                    "client_credentials iwa:ntlm authorization_code urn:ietf:params:oauth:grant-type:jwt-bearer");
            prepStmt.setLong(10, 3600L);
            prepStmt.setLong(11, 3600L);
            prepStmt.setLong(12, 84600L);
            prepStmt.execute();
            connection.commit();
        }

    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }
}
