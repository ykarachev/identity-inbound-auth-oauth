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
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.SQLQueries;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.util.DAOConstants;
import org.wso2.carbon.identity.oauth2.dao.util.DAOUtils;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Set;
import java.util.UUID;

import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertNull;
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

    private static final String CALLBACK_URL = "http://localhost:8080/sample/oauth2client";

    private static final String SAMPLE_TENANT_DOMAIN = "wso2.com";

    private static final int SAMPLE_TENANT_ID = 1;

    private static final String SAMPLE_DOMAIN = "SAMPLE_DOMAIN";

    private static final String INVALID_SCOPE = "INVALID_SCOPE";

    private TokenMgtDAO tokenMgtDAO;

    @Mock
    private OAuthServerConfiguration mockedOAuthServerConfiguration;

    @Mock
    private RealmService mockedRealmService;

    @Mock
    private ApplicationManagementService mockedApplicationManagementService;

    @Mock
    private TenantManager mockedTenantManager;

    @Mock
    private ServiceProvider mockedServiceProvider;

    @Mock
    private LocalAndOutboundAuthenticationConfig mockedLocalAndOutboundAuthenticationConfig;

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

        OAuthComponentServiceHolder.getInstance().setRealmService(mockedRealmService);
        when(mockedRealmService.getTenantManager()).thenReturn(mockedTenantManager);
        when(mockedTenantManager.getTenantId(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)).thenReturn
                (MultitenantConstants.SUPER_TENANT_ID);
        when(mockedTenantManager.getTenantId(SAMPLE_TENANT_DOMAIN)).thenReturn(SAMPLE_TENANT_ID);

        when(mockedApplicationManagementService.getServiceProviderByClientId(anyString(), anyString(), anyString()))
                .thenReturn(mockedServiceProvider);
        when(mockedServiceProvider.getLocalAndOutBoundAuthenticationConfig()).thenReturn
                (mockedLocalAndOutboundAuthenticationConfig);
        OAuth2ServiceComponentHolder.setApplicationMgtService(mockedApplicationManagementService);
    }

    @DataProvider(name = "storeAuthorizationCodeDataProvider")
    public Object[][] storeAuthorizationCodeData() {

        return new Object[][]{
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID
                },
        };
    }

    @Test(dataProvider = "storeAuthorizationCodeDataProvider")
    public void testStoreAuthorizationCode(String callbackUrl, String tenantDomain, int tenantId) throws
            IdentityOAuth2Exception, SQLException, IdentityOAuthAdminException {
        persistAuthorizationCode(UUID.randomUUID().toString(), UUID.randomUUID().toString(),
                UUID.randomUUID().toString(), callbackUrl, tenantDomain, tenantId);
    }

    @DataProvider(name = "persistAuthorizationCodeDataProvider")
    public Object[][] persistAuthorizationCodeData() {

        return new Object[][]{
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID
                },
        };
    }

    @Test(dataProvider = "persistAuthorizationCodeDataProvider")
    public void testPersistAuthorizationCode(String callbackUrl, String tenantDomain, int tenantId) throws
            IdentityOAuth2Exception, SQLException, IdentityOAuthAdminException {
        persistAuthorizationCode(UUID.randomUUID().toString(), UUID.randomUUID().toString(),
                UUID.randomUUID().toString(), callbackUrl, tenantDomain, tenantId);
    }

    @DataProvider(name = "deactivateAuthorizationCodeDataProvider")
    public Object[][] deactivateAuthorizationCodeData() {

        return new Object[][]{
                {
                        CALLBACK_URL,
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID
                },
                {
                        CALLBACK_URL,
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID
                },
        };
    }

    @Test(dataProvider = "deactivateAuthorizationCodeDataProvider")
    public void testDeactivateAuthorizationCode(String callbackUrl, String tenantDomain, int tenantId) throws
            SQLException, IdentityOAuth2Exception {
        createApplication(UUID.randomUUID().toString(), UUID.randomUUID().toString(), tenantId);
        String authzCode = UUID.randomUUID().toString();
        persistAuthorizationCode(UUID.randomUUID().toString(), UUID.randomUUID().toString(), authzCode, callbackUrl,
                tenantDomain, tenantId);

        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            tokenMgtDAO.deactivateAuthorizationCode(authzCode, UUID.randomUUID().toString());
        }
        assertTrue("INACTIVE".equals(getAuthzCodeStatusByCode(authzCode)), "Failed to deactivate authz code.");
    }

    @DataProvider(name = "storeAccessTokenDataProvider")
    public Object[][] storeAccessTokenData() {

        return new Object[][]{
                // Change grant
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.CLIENT_CREDENTIALS,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.IMPLICIT,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.IWA_NTLM,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.PASSWORD,
                },
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.TOKEN,
                },
                // Change Domain
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                },
                // Change Tenant
                {
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                },
                // Change user type
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                },
        };
    }

    @Test(dataProvider = "storeAccessTokenDataProvider")
    public void testStoreAccessToken(String tenantDomain, int tenantId, String userStoreDomain, String applicationType,
                                     String grantType) throws IdentityOAuth2Exception, SQLException {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        mockStatic(IdentityUtil.class);

        String consumerKey = UUID.randomUUID().toString();
        createApplication(consumerKey, UUID.randomUUID().toString(), tenantId);

        AuthenticatedUser authenticatedUser = getAuthenticatedUser(tenantDomain, userStoreDomain);
        AccessTokenDO accessTokenDO = getAccessTokenDO(consumerKey, authenticatedUser, applicationType, tenantId,
                grantType);
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            tokenMgtDAO.storeAccessToken(accessTokenDO.getAccessToken(), consumerKey, accessTokenDO, connection,
                    userStoreDomain);
        }
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            Set<String> accessTokens = tokenMgtDAO.getAccessTokensForUser(authenticatedUser);
            assertTrue(accessTokens != null && accessTokens.contains(accessTokenDO.getAccessToken()), "Failed to " +
                    "persist access token");
        }
    }

    @Test(dataProvider = "storeAccessTokenDataProvider")
    public void testStoreAccessTokenWhileExpiringTheExisting(String tenantDomain, int tenantId, String userStoreDomain,
                                                             String applicationType, String grantType)
            throws IdentityException, SQLException {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        mockStatic(IdentityUtil.class);

        String consumerKey = UUID.randomUUID().toString();
        createApplication(consumerKey, UUID.randomUUID().toString(), tenantId);
        AuthenticatedUser authenticatedUser = getAuthenticatedUser(tenantDomain, userStoreDomain);

        AccessTokenDO existingAccessTokenDO = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            tokenMgtDAO.storeAccessToken(existingAccessTokenDO.getAccessToken(), consumerKey, existingAccessTokenDO,
                    connection, userStoreDomain);
        }

        AccessTokenDO newAccessTokenDO = getAccessTokenDO(consumerKey, authenticatedUser, applicationType, tenantId,
                grantType);
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            tokenMgtDAO.storeAccessToken(newAccessTokenDO.getAccessToken(), consumerKey, newAccessTokenDO,
                    existingAccessTokenDO, userStoreDomain);
        }

        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            Set<String> accessTokens = tokenMgtDAO.getAccessTokensForUser(authenticatedUser);
            assertTrue(accessTokens != null && accessTokens.contains(newAccessTokenDO.getAccessToken()), "Failed to " +
                    "persist access token.");
        }
    }

    @Test(dataProvider = "storeAccessTokenDataProvider")
    public void testPersistAccessToken(String tenantDomain, int tenantId, String userStoreDomain,
                                       String applicationType, String grantType) throws IdentityException,
            SQLException {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        mockStatic(IdentityUtil.class);

        String consumerKey = UUID.randomUUID().toString();
        createApplication(consumerKey, UUID.randomUUID().toString(), tenantId);
        AuthenticatedUser authenticatedUser = getAuthenticatedUser(tenantDomain, userStoreDomain);

        AccessTokenDO existingAccessTokenDO = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            tokenMgtDAO.storeAccessToken(existingAccessTokenDO.getAccessToken(), consumerKey, existingAccessTokenDO,
                    connection, userStoreDomain);
        }

        AccessTokenDO newAccessTokenDO = getAccessTokenDO(consumerKey, authenticatedUser, applicationType, tenantId,
                grantType);
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            assertTrue(tokenMgtDAO.persistAccessToken(newAccessTokenDO.getAccessToken(), consumerKey, newAccessTokenDO,
                    existingAccessTokenDO, userStoreDomain), "Failed to persist access token.");
        }
    }

    @DataProvider(name = "retrieveLatestAccessTokenDataProvider")
    public Object[][] retrieveLatestAccessTokenData() {

        return new Object[][]{
                // Change grant
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        "scope1 scope2",
                        true
                },
                // Change Domain
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        "scope1 scope2",
                        true
                },
                // Change Tenant
                {
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        "scope1 scope2",
                        true
                },
                // Change user type
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        "scope1 scope2",
                        true
                },
                // Change grant
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        "scope1 scope2",
                        false
                },
                // Change Domain
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        SAMPLE_DOMAIN,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        "scope1 scope2",
                        false
                },
                // Change Tenant
                {
                        SAMPLE_TENANT_DOMAIN,
                        SAMPLE_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION_USER,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        "scope1 scope2",
                        false
                },
                // Change user type
                {
                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                        MultitenantConstants.SUPER_TENANT_ID,
                        UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME,
                        OAuthConstants.UserType.APPLICATION,
                        OAuthConstants.GrantTypes.AUTHORIZATION_CODE,
                        "scope1 scope2",
                        false
                },
        };
    }

    @Test(dataProvider = "retrieveLatestAccessTokenDataProvider")
    public void testRetrieveLatestAccessToken(String tenantDomain, int tenantId, String userStoreDomain,
                                              String applicationType, String grantType, String scope,
                                              boolean includeExpiredTokens)
            throws IdentityOAuth2Exception, SQLException {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());
        mockStatic(IdentityUtil.class);

        String consumerKey = UUID.randomUUID().toString();
        createApplication(consumerKey, UUID.randomUUID().toString(), tenantId);
        AuthenticatedUser authenticatedUser = getAuthenticatedUser(tenantDomain, userStoreDomain);

        AccessTokenDO expiredAccessToken = getAccessTokenDO(consumerKey, authenticatedUser, applicationType,
                tenantId, grantType);
        expiredAccessToken.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED);
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            tokenMgtDAO.storeAccessToken(expiredAccessToken.getAccessToken(), consumerKey, expiredAccessToken,
                    connection, userStoreDomain);
        }

        if (includeExpiredTokens) {
            if (!INVALID_SCOPE.equals(scope)) {
                try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
                    mockStatic(IdentityDatabaseUtil.class);
                    when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
                    AccessTokenDO accessTokenDO = tokenMgtDAO.retrieveLatestAccessToken(consumerKey, authenticatedUser,
                            userStoreDomain, scope, true);
                    assertTrue(accessTokenDO != null && expiredAccessToken.getAccessToken().equals(accessTokenDO
                            .getAccessToken()), "Failed to retrieve latest token.");
                }
            } else {
                try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
                    mockStatic(IdentityDatabaseUtil.class);
                    when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
                    assertNull(tokenMgtDAO.retrieveLatestAccessToken(consumerKey, authenticatedUser, userStoreDomain,
                            scope, true), "Invalid access token.");
                }
            }
        } else {
            AccessTokenDO newAccessTokenDO = getAccessTokenDO(consumerKey, authenticatedUser, applicationType, tenantId,
                    grantType);
            try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
                mockStatic(IdentityDatabaseUtil.class);
                when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
                tokenMgtDAO.persistAccessToken(newAccessTokenDO.getAccessToken(), consumerKey, newAccessTokenDO,
                        expiredAccessToken, userStoreDomain);
            }

            try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
                mockStatic(IdentityDatabaseUtil.class);
                when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
                AccessTokenDO accessTokenDO = tokenMgtDAO.retrieveLatestAccessToken(consumerKey, authenticatedUser,
                        userStoreDomain, scope, false);
                assertTrue(newAccessTokenDO.getAccessToken().equals(accessTokenDO.getAccessToken()), "Failed to " +
                        "retrieve latest access token");
            }
        }
    }

    private void persistAuthorizationCode(String consumerKey, String authzCodeId, String authzCode, String callbackUrl,
                                          String tenantDomain, int tenantId) throws IdentityOAuth2Exception,
            SQLException {
        createApplication(consumerKey, UUID.randomUUID().toString(), tenantId);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(new PlainTextPersistenceProcessor());

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("sampleUser");
        authenticatedUser.setTenantDomain(tenantDomain);
        authenticatedUser.setUserStoreDomain(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);

        AuthzCodeDO authzCodeDO = new AuthzCodeDO(authenticatedUser, new String[]{"scope1", "scope2"},
                new Timestamp(System.currentTimeMillis()), 3600L, callbackUrl, consumerKey, authzCode, authzCodeId,
                null, null);
        try (Connection connection = DAOUtils.getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            tokenMgtDAO.storeAuthorizationCode(authzCode, consumerKey, callbackUrl, authzCodeDO);
            assertNotNull(tokenMgtDAO.getAuthzCodeByCodeId(authzCodeId), "Failed to persist authorize code.");
        }
    }

    private void createApplication(String consumerKey, String consumerSecret, int tenantId)
            throws SQLException {
        try (Connection connection = DAOUtils.getConnection(DB_NAME);
             PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.ADD_OAUTH_APP)) {
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

    private String getAuthzCodeStatusByCode(String authzCode) throws SQLException {
        try (Connection connection = DAOUtils.getConnection(DB_NAME);
             PreparedStatement prepStmt = connection.prepareStatement(DAOConstants.AUTHZ_CODE_STATUS_BY_CODE)) {
            prepStmt.setString(1, authzCode);
            try (ResultSet resultSet = prepStmt.executeQuery()) {
                if (resultSet.next()) {
                    return resultSet.getString(1);
                }
            }
        }
        return null;
    }

    private AuthenticatedUser getAuthenticatedUser(String tenantDomain, String userStoreDomain) {
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("sampleUser");
        authenticatedUser.setTenantDomain(tenantDomain);
        authenticatedUser.setUserStoreDomain(userStoreDomain);
        return authenticatedUser;
    }

    private AccessTokenDO getAccessTokenDO(String consumerKey, AuthenticatedUser authenticatedUser, String
            applicationType, int tenantId, String grantType) {
        AccessTokenDO accessTokenDO = new AccessTokenDO(consumerKey, authenticatedUser, new String[]{"scope1",
                "scope2"}, new Timestamp(System.currentTimeMillis()), new Timestamp(System.currentTimeMillis()),
                3600L, 3600L, applicationType);
        accessTokenDO.setAccessToken(UUID.randomUUID().toString());
        accessTokenDO.setRefreshToken(UUID.randomUUID().toString());
        accessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
        accessTokenDO.setTenantID(tenantId);
        accessTokenDO.setTokenId(UUID.randomUUID().toString());
        accessTokenDO.setGrantType(grantType);
        return accessTokenDO;
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }
}
