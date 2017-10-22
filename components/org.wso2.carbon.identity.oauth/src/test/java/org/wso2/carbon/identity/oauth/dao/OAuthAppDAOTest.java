/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.dao;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.test.utils.CommonTestUtils;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

/*
 * Unit tests for OAuthAppDAO
 */
@PrepareForTest({IdentityDatabaseUtil.class, OAuthServerConfiguration.class, OAuthConsumerDAO.class,
        OAuthUtil.class, OAuth2ServiceComponentHolder.class, IdentityTenantUtil.class, IdentityUtil.class,
        MultitenantUtils.class, OAuthComponentServiceHolder.class})
public class OAuthAppDAOTest extends TestOAuthDAOBase {

    private static final String CLIENT_ID = "ca19a540f544777860e44e75f605d927";
    private static final String SECRET = "87n9a540f544777860e44e75f605d435";
    private static final String APP_NAME = "myApp";
    private static final String USER_NAME = "user1";
    private static final String APP_STATE = "ACTIVE";
    private static final String CALLBACK = "http://localhost:8080/redirect";
    private static final String DB_NAME = "testDB";

    @Mock
    private TenantManager mockedTenantManager;

    @Mock
    private AuthenticatedUser mockedAuthenticatedUser;

    @Mock
    private RealmService mockedRealmService;

    @Mock
    private OAuthAppDO mockedAppDo;

    @Mock
    private OAuthServerConfiguration mockedServerConfig;

    @Mock
    private AuthenticatedUser mockedUser;

    @Mock
    private OAuthComponentServiceHolder mockedOAuthComponentServiceHolder;

    @BeforeClass
    public void setUp() throws Exception {

        initiateH2Base(DB_NAME, getFilePath("h2.sql"));
        createBase(CLIENT_ID, SECRET, USER_NAME, APP_NAME, CALLBACK, APP_STATE);
    }

    @DataProvider(name = "pkceEnabledDataProvider")
    public Object[][] provideData() throws Exception {
        return new Object[][]{
                {true},
                {false}
        };
    }

    @Test(dataProvider = "pkceEnabledDataProvider")
    public void testAddOAuthApplication(Boolean enablePKCE) throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        when(mockedAppDo.getUser()).thenReturn(mockedUser);
        when(mockedUser.getUserName()).thenReturn(USER_NAME);
        when(mockedUser.getUserStoreDomain()).thenReturn("fakeUserStoreDomain");

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId("PRIMARY")).thenReturn(-12345);
        mockStatic(OAuth2ServiceComponentHolder.class);
        when(OAuth2ServiceComponentHolder.isPkceEnabled()).thenReturn(enablePKCE);

        try (Connection connection = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
            mockStatic(IdentityUtil.class);
            when(IdentityUtil.isUserStoreInUsernameCaseSensitive(USER_NAME, -12345)).thenReturn(false);

            OAuthAppDAO AppDAO = new OAuthAppDAO();
            AppDAO.addOAuthApplication(mockedAppDo);
        }
    }

    @Test(dataProvider = "pkceEnabledDataProvider", expectedExceptions = IdentityOAuthAdminException.class)
    public void testAddOAuthApplicationWithExceptions(Boolean enablePKCE) throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        when(mockedAppDo.getUser()).thenReturn(mockedUser);
        when(mockedUser.getUserName()).thenReturn(USER_NAME);
        when(mockedUser.getUserStoreDomain()).thenReturn("fakeUserStoreDomain");

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId("PRIMARY")).thenReturn(-12345);

        mockStatic(OAuth2ServiceComponentHolder.class);
        when(OAuth2ServiceComponentHolder.isPkceEnabled()).thenReturn(enablePKCE);

        try (Connection connection = getConnection(DB_NAME)) {
            Connection connection1 = spy(connection);
            doThrow(new SQLException()).when(connection1).commit();
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);
            mockStatic(IdentityUtil.class);
            when(IdentityUtil.isUserStoreInUsernameCaseSensitive(USER_NAME, -12345)).thenReturn(false);

            OAuthAppDAO AppDAO = new OAuthAppDAO();
            AppDAO.addOAuthApplication(mockedAppDo);
        }
    }

    @Test
    public void testAddOAuthConsumer() throws Exception {

        String newKey = "fakeKey";
        String user = "fakeUser";
        String secret = "fakeSecret";

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try (Connection connection = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

            mockStatic(OAuthUtil.class);
            when(OAuthUtil.getRandomNumber()).thenReturn(secret).thenReturn(newKey);

            OAuthAppDAO AppDAO = new OAuthAppDAO();
            assertEquals(AppDAO.addOAuthConsumer(user, -1234, "PRIMARY"),
                    new String[]{newKey, secret});
        }
    }

    @Test(expectedExceptions = IdentityOAuthAdminException.class)
    public void testAddOAuthConsumerWithExceptions() throws Exception {

        String newKey = "fakeKey";
        String user = "fakeUser";
        String secret = "fakeSecret";

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try (Connection connection = getConnection(DB_NAME)) {
            Connection connection1 = spy(connection);
            doThrow(new SQLException()).when(connection1).commit();
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);
            mockStatic(OAuthUtil.class);
            when(OAuthUtil.getRandomNumber()).thenReturn(secret).thenReturn(newKey);

            OAuthAppDAO AppDAO = new OAuthAppDAO();
            assertEquals(AppDAO.addOAuthConsumer(user, -1234, "PRIMARY"),
                    new String[]{newKey, secret});
        }
    }

    @Test(dataProvider = "pkceEnabledDataProvider")
    public void testUpdateConsumerApplication(Boolean enablePKCE) throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        mockStatic(OAuth2ServiceComponentHolder.class);
        when(OAuth2ServiceComponentHolder.isPkceEnabled()).thenReturn(enablePKCE);

        try (Connection connection = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

            OAuthAppDAO AppDAO = new OAuthAppDAO();
            AppDAO.updateConsumerApplication(mockedAppDo);
        }
    }

    @Test(dataProvider = "pkceEnabledDataProvider", expectedExceptions = IdentityOAuthAdminException.class)
    public void testUpdateConsumerApplicationWithExceptions(Boolean enablePKCE) throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        mockStatic(OAuth2ServiceComponentHolder.class);
        when(OAuth2ServiceComponentHolder.isPkceEnabled()).thenReturn(enablePKCE);

        try (Connection connection = getConnection(DB_NAME)) {
            Connection connection1 = spy(connection);
            doThrow(new SQLException()).when(connection1).commit();
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);

            OAuthAppDAO AppDAO = new OAuthAppDAO();
            AppDAO.updateConsumerApplication(mockedAppDo);
        }
    }

    @Test
    public void testRemoveConsumerApplication() throws Exception {

        String GET_SECRET_SQL = "SELECT CONSUMER_SECRET FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY=?";

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try (Connection connection = getConnection(DB_NAME)) {
            PreparedStatement statement = connection.prepareStatement(GET_SECRET_SQL);
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

            OAuthAppDAO AppDAO = new OAuthAppDAO();
            AppDAO.removeConsumerApplication(CLIENT_ID);
            statement.setString(1, CLIENT_ID);

            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    assertNull(resultSet.getString(1), "Checking whether the CONSUMER_SECRET is successfully deleted.");
                }
            }
        }
    }

    @Test(expectedExceptions = IdentityOAuthAdminException.class)
    public void testRemoveConsumerApplicationWithExceptions() throws Exception {

        String GET_SECRET_SQL = "SELECT CONSUMER_SECRET FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY=?";

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try (Connection connection = getConnection(DB_NAME)) {
            Connection connection1 = spy(connection);
            doThrow(new SQLException()).when(connection1).commit();
            PreparedStatement statement = connection.prepareStatement(GET_SECRET_SQL);
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);

            OAuthAppDAO AppDAO = new OAuthAppDAO();
            AppDAO.removeConsumerApplication(CLIENT_ID);
            statement.setString(1, CLIENT_ID);

            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    assertNull(resultSet.getString(1), "Checking whether the CONSUMER_SECRET is successfully deleted.");
                }
            }
        }
    }

    @Test
    public void testUpdateOAuthConsumerApp() throws Exception {

        String GET_APP_SQL = "SELECT APP_NAME FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY=?";

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try (Connection connection1 = getConnection(DB_NAME)) {
            PreparedStatement statement = connection1.prepareStatement(GET_APP_SQL);
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);

            OAuthAppDAO AppDAO = new OAuthAppDAO();
            AppDAO.updateOAuthConsumerApp(APP_NAME, CLIENT_ID);
            statement.setString(1, CLIENT_ID);

            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    assertEquals(resultSet.getString(1), APP_NAME, "Checking whether the table " +
                            "is updated with the passed appName.");
                }
            }
        }
    }

    @Test(expectedExceptions = IdentityApplicationManagementException.class)
    public void testUpdateOAuthConsumerAppWithExceptions() throws Exception {

        String GET_APP_SQL = "SELECT APP_NAME FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY=?";

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try (Connection connection1 = getConnection(DB_NAME)) {
            Connection connection2 = spy(connection1);
            doThrow(new SQLException()).when(connection2).commit();
            PreparedStatement statement = connection1.prepareStatement(GET_APP_SQL);
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection2);

            OAuthAppDAO AppDAO = new OAuthAppDAO();
            AppDAO.updateOAuthConsumerApp(APP_NAME, CLIENT_ID);
            statement.setString(1, CLIENT_ID);

            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    assertEquals(resultSet.getString(1), APP_NAME, "Checking whether the table " +
                            "is updated with the passed appName.");
                }
            }
        }
    }

    @Test
    public void testGetConsumerAppState() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try (Connection connection = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

            OAuthAppDAO AppDAO = new OAuthAppDAO();
            assertEquals(AppDAO.getConsumerAppState(CLIENT_ID), APP_STATE, "Checking the APP_STATE for the " +
                    "given CONSUMER_KEY.");
        }
    }

    @Test(expectedExceptions = IdentityOAuthAdminException.class)
    public void testGetConsumerAppStateWithExceptions() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try (Connection connection = getConnection(DB_NAME)) {
            Connection connection1 = spy(connection);
            doThrow(new SQLException()).when(connection1).commit();
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);

            OAuthAppDAO AppDAO = new OAuthAppDAO();
            assertEquals(AppDAO.getConsumerAppState(CLIENT_ID), APP_STATE, "Checking the APP_STATE for the " +
                    "given CONSUMER_KEY.");
        }
    }

    @Test
    public void testUpdateConsumerAppState() throws Exception {

        String GET_APP_STATE_SQL = "SELECT APP_STATE FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY=?";

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try (Connection connection1 = getConnection(DB_NAME);
             PreparedStatement statement = connection1.prepareStatement(GET_APP_STATE_SQL)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);

            OAuthAppDAO AppDAO = new OAuthAppDAO();
            AppDAO.updateConsumerAppState(CLIENT_ID, APP_STATE);
            statement.setString(1, CLIENT_ID);

            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    assertEquals(resultSet.getString(1), APP_STATE, "Checking whether the table " +
                            "is updated with the passed APP_STATE.");
                }
            }
        }

    }

    @DataProvider(name = "booleanTests")
    public Object[][] booleanTest() throws Exception {
        return new Object[][]{
                {true, true},
                {true, false},
                {false, true},
                {false, false}
        };
    }

    @Test(dataProvider = "booleanTests")
    public void testGetOAuthConsumerAppsOfUser(Boolean enablePKCE, Boolean isSensitive) throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        mockStatic(OAuthComponentServiceHolder.class);
        when(OAuthComponentServiceHolder.getInstance()).thenReturn(mockedOAuthComponentServiceHolder);
        when(mockedOAuthComponentServiceHolder.getRealmService()).thenReturn(mockedRealmService);

        mockStatic(MultitenantUtils.class);
        when(MultitenantUtils.getTenantAwareUsername(USER_NAME)).thenReturn(USER_NAME);
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.isUserStoreInUsernameCaseSensitive(USER_NAME)).thenReturn(isSensitive);

        mockStatic(OAuth2ServiceComponentHolder.class);
        when(OAuth2ServiceComponentHolder.isPkceEnabled()).thenReturn(enablePKCE);

        when(mockedRealmService.getTenantManager()).thenReturn(mockedTenantManager);
        when(mockedTenantManager.getDomain(-12345)).thenReturn("PRIMARY");

        try (Connection connection1 = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);

            OAuthAppDAO AppDAO = new OAuthAppDAO();
            AppDAO.getOAuthConsumerAppsOfUser(USER_NAME, -12345);
        }
    }

    @Test(dataProvider = "booleanTests", expectedExceptions = IdentityOAuthAdminException.class)
    public void testGetOAuthConsumerAppsOfUserWithExceptions(Boolean enablePKCE, Boolean isSensitive) throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        mockStatic(OAuthComponentServiceHolder.class);
        when(OAuthComponentServiceHolder.getInstance()).thenReturn(mockedOAuthComponentServiceHolder);
        when(mockedOAuthComponentServiceHolder.getRealmService()).thenReturn(mockedRealmService);

        mockStatic(MultitenantUtils.class);
        when(MultitenantUtils.getTenantAwareUsername(USER_NAME)).thenReturn(USER_NAME);
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.isUserStoreInUsernameCaseSensitive(USER_NAME)).thenReturn(isSensitive);

        mockStatic(OAuth2ServiceComponentHolder.class);
        when(OAuth2ServiceComponentHolder.isPkceEnabled()).thenReturn(enablePKCE);

        when(mockedRealmService.getTenantManager()).thenReturn(mockedTenantManager);
        when(mockedTenantManager.getDomain(-12345)).thenReturn("PRIMARY");

        try (Connection connection = getConnection(DB_NAME)) {
            Connection connection1 = spy(connection);
            doThrow(new SQLException()).when(connection1).commit();
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);

            OAuthAppDAO AppDAO = new OAuthAppDAO();
            AppDAO.getOAuthConsumerAppsOfUser(USER_NAME, -12345);
        }
    }

    @Test(dataProvider = "pkceEnabledDataProvider")
    public void testGetAppInformation(Boolean enablePKCE) throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        mockStatic(OAuth2ServiceComponentHolder.class);
        when(OAuth2ServiceComponentHolder.isPkceEnabled()).thenReturn(enablePKCE);

        whenNew(OAuthAppDO.class).withNoArguments().thenReturn(mockedAppDo);

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantDomain(-12345)).thenReturn("PRIMARY");
        whenNew(AuthenticatedUser.class).withNoArguments().thenReturn(mockedAuthenticatedUser);

        try (Connection connection1 = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);

            OAuthAppDAO AppDAO = new OAuthAppDAO();
            assertNotNull(AppDAO.getAppInformation(CLIENT_ID));
        }
    }

    @Test(dataProvider = "pkceEnabledDataProvider", expectedExceptions = IdentityOAuth2Exception.class)
    public void testGetAppInformationWithExceptions(Boolean enablePKCE) throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        mockStatic(OAuth2ServiceComponentHolder.class);
        when(OAuth2ServiceComponentHolder.isPkceEnabled()).thenReturn(enablePKCE);

        whenNew(OAuthAppDO.class).withNoArguments().thenReturn(mockedAppDo);

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantDomain(-12345)).thenReturn("PRIMARY");
        whenNew(AuthenticatedUser.class).withNoArguments().thenReturn(mockedAuthenticatedUser);

        try (Connection connection = getConnection(DB_NAME)) {
            Connection connection1 = spy(connection);
            doThrow(new SQLException()).when(connection1).commit();
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);

            OAuthAppDAO AppDAO = new OAuthAppDAO();
            assertNotNull(AppDAO.getAppInformation(CLIENT_ID));
        }
    }

    @Test(dataProvider = "pkceEnabledDataProvider")
    public void testGetAppInformationByAppName(Boolean enablePKCE) throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        mockStatic(OAuth2ServiceComponentHolder.class);
        when(OAuth2ServiceComponentHolder.isPkceEnabled()).thenReturn(enablePKCE);

        CommonTestUtils.initPrivilegedCarbonContext("PRIMARY", -1234, USER_NAME);

        whenNew(AuthenticatedUser.class).withNoArguments().thenReturn(mockedAuthenticatedUser);
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantDomain(-12345)).thenReturn("PRIMARY");

        try (Connection connection1 = getConnection(DB_NAME)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);

            OAuthAppDAO AppDAO = new OAuthAppDAO();
            AppDAO.getAppInformationByAppName(APP_NAME);
        }
    }

    @Test(dataProvider = "pkceEnabledDataProvider", expectedExceptions = IdentityOAuth2Exception.class)
    public void testGetAppInformationByAppNameWithExceptions(Boolean enablePKCE) throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        mockStatic(OAuth2ServiceComponentHolder.class);
        when(OAuth2ServiceComponentHolder.isPkceEnabled()).thenReturn(enablePKCE);

        CommonTestUtils.initPrivilegedCarbonContext("PRIMARY", -1234, USER_NAME);

        whenNew(AuthenticatedUser.class).withNoArguments().thenReturn(mockedAuthenticatedUser);
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantDomain(-12345)).thenReturn("PRIMARY");

        try (Connection connection = getConnection(DB_NAME)) {
            Connection connection1 = spy(connection);
            doThrow(new SQLException()).when(connection1).commit();
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);

            OAuthAppDAO AppDAO = new OAuthAppDAO();
            AppDAO.getAppInformationByAppName(APP_NAME);
        }
    }

}
