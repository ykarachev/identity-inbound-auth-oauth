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

import org.apache.commons.dbcp.BasicDataSource;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.dao.OpenIDUserRPDAO;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;

import java.io.File;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

@PrepareForTest({ IdentityTenantUtil.class, IdentityDatabaseUtil.class, OAuthServerConfiguration.class})
public class OpenIDConnectUserRPStoreTest extends PowerMockTestCase {

    private static final String ADD_OAUTH_APP_SQL = "INSERT INTO IDN_OAUTH_CONSUMER_APPS " +
            "(CONSUMER_KEY, CONSUMER_SECRET, USERNAME, TENANT_ID, USER_DOMAIN, APP_NAME, OAUTH_VERSION," +
            " CALLBACK_URL, GRANT_TYPES) VALUES (?,?,?,?,?,?,?,?,?) ";

    private static final String RETRIEVE_PERSISTED_USER_SQL = "SELECT USER_NAME FROM IDN_OPENID_USER_RPS";

    private  AuthenticatedUser user;
    private OpenIDConnectUserRPStore store;
    private Connection connection;
    private String clientId;
    private String secret;
    private String appName;
    private String username;
    private String tenantDomain;

    @Mock
    OpenIDUserRPDAO openIDUserRPDAO;

    @Mock
    PreparedStatement preparedStatement;

    @Mock
    OAuthServerConfiguration oAuthServerConfiguration;

    @Mock
    TokenPersistenceProcessor tokenPersistenceProcessor;

    @Mock
    ResultSet resultSet;

    @BeforeTest
    public void setUp() throws Exception {

        System.setProperty("carbon.home", new File("src/test/resources/carbon_home").getAbsolutePath());
        clientId = "ca19a540f544777860e44e75f605d927";
        secret = "87n9a540f544777860e44e75f605d435";
        appName = "myApp";
        username = "user1";
        tenantDomain = "carbon.super";

        user = new AuthenticatedUser();
        user.setTenantDomain(tenantDomain);
        user.setAuthenticatedSubjectIdentifier(username);

        store = OpenIDConnectUserRPStore.getInstance();

        initiateInMemoryH2();
        createOAuthApp();
    }

    @AfterTest
    public void cleanData() throws Exception {
        connection.close();
    }

    @DataProvider(name = "provideStoreDataToPut")
    public Object[][] provideStoreDataToPut() {

        return new Object[][] {
                { username, clientId },
                { null, clientId },
                { null, "dummyClientId"}
        };
    }

    @Test(dataProvider = "provideStoreDataToPut")
    public void testPutUserRPToStore(String usernameValue, String consumerKey) throws Exception {

        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(oAuthServerConfiguration.getPersistenceProcessor()).thenReturn(tokenPersistenceProcessor);
        when(tokenPersistenceProcessor.getProcessedClientId(anyString())).thenAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                return (String) invocation.getArguments()[0];
            }
        });

        user.setUserName(usernameValue);
        try {
            store.putUserRPToStore(user, appName, true, consumerKey);
        } catch (OAuthSystemException e) {
            // Exception thrown because the app does not exist
            Assert.assertTrue(!clientId.equals(consumerKey), "Unexpected exception thrown: " + e.getMessage());
        }

        PreparedStatement statement = null;
        ResultSet rs = null;
        String name = null;
         try {
             statement = connection.prepareStatement(RETRIEVE_PERSISTED_USER_SQL);
             rs = statement.executeQuery();
             if (rs.next()) {
                 name = rs.getString(1);
             }
         } finally {
             if (statement != null) {
                 statement.close();
             }
             if (rs != null) {
                 rs.close();
             }
         }
         Assert.assertEquals(name, username, "Data not added to the store");
    }

    @DataProvider(name = "provideDataToCheckApproved")
    public Object[][] provideDataToCheckApproved() {

        return new Object[][] {
                { username, clientId, appName, true },
                { null, clientId, appName, true },
                { null, clientId, "dummyAppName", false },
                { null, "dummyClientId", appName, false}
        };
    }

    @Test(dataProvider = "provideDataToCheckApproved", dependsOnMethods = {"testPutUserRPToStore"})
    public void testHasUserApproved(String usernameValue, String consumerKey, String app, boolean expected)
            throws Exception {

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);

        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(oAuthServerConfiguration.getPersistenceProcessor()).thenReturn(tokenPersistenceProcessor);
        when(tokenPersistenceProcessor.getProcessedClientId(anyString())).thenAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                return (String) invocation.getArguments()[0];
            }
        });

        user.setUserName(usernameValue);
        boolean result;
        try {
            result = store.hasUserApproved(user, app, consumerKey);
            Assert.assertEquals(result, expected);
        } catch (OAuthSystemException e) {
            // Exception thrown because the app does not exist
            Assert.assertTrue(!clientId.equals(consumerKey), "Unexpected exception thrown: " + e.getMessage());
        }
    }

    public void initiateInMemoryH2() throws Exception {
        BasicDataSource dataSource = new BasicDataSource();

        dataSource.setDriverClassName("org.h2.Driver");
        dataSource.setUsername("username");
        dataSource.setPassword("password");
        dataSource.setUrl("jdbc:h2:mem:test");

        connection = dataSource.getConnection();
        connection.createStatement().executeUpdate("RUNSCRIPT FROM 'src/test/resources/dbscripts/h2.sql'");
    }

    private void createOAuthApp() throws Exception {

        PreparedStatement statement = null;
        try {
            statement = connection.prepareStatement(ADD_OAUTH_APP_SQL);
            statement.setString(1, clientId);
            statement.setString(2, secret);
            statement.setString(3, username);
            statement.setInt(4, -1234);
            statement.setString(5, "PRIMARY");
            statement.setString(6, appName);
            statement.setString(7, "OAuth-2.0");
            statement.setString(8, null);
            statement.setString(9, "password");
            statement.execute();
        } finally {
            if (statement != null){
                statement.close();
            }
        }
    }
}
