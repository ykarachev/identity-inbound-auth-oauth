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
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

/*
 * Unit tests for OAuthAppDAO
 */
@PrepareForTest({IdentityDatabaseUtil.class, OAuthServerConfiguration.class, OAuthConsumerDAO.class})
public class OAuthAppDAOTest extends TestOAuthDAOBase {

    private static final String clientId = "ca19a540f544777860e44e75f605d927";
    private static final String secret = "87n9a540f544777860e44e75f605d435";
    private static final String appName = "myApp";
    private static final String username = "user1";
    private static final String appState = "ACTIVE";
    private static final String callback = "http://localhost:8080/redirect";
    private static final String DB_Name = "testDB";

    @Mock
    private OAuthServerConfiguration mockedServerConfig;

    @BeforeClass
    public void setUp() throws Exception {

        initiateH2Base(DB_Name, getFilePath("h2.sql"));
        createBase(clientId, secret, username, appName, callback, appState);
    }

    @Test
    public void testRemoveConsumerApplication() throws Exception {

        String GET_SECRET = "SELECT CONSUMER_SECRET FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY=?";
        String secret = null;

        PreparedStatement statement = null;
        ResultSet resultSet = null;

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try(Connection connection = getConnection(DB_Name)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

            OAuthAppDAO AppDAO = new OAuthAppDAO();
            AppDAO.removeConsumerApplication(clientId);

            try {
                statement = connection.prepareStatement(GET_SECRET);
                statement.setString(1, clientId);
                resultSet = statement.executeQuery();
                if(resultSet.next()) {
                    secret = resultSet.getString(1);
                }
            } finally {
                IdentityDatabaseUtil.closeAllConnections(connection, resultSet, statement);
            }
            assertNull(secret, "Checking whether the CONSUMER_SECRET is successfully deleted.");
        }
    }

    @Test
    public void testUpdateOAuthConsumerApp() throws Exception {

        String GET_APP = "SELECT APP_NAME FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY=?";

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try(Connection connection1 = getConnection(DB_Name);
            PreparedStatement statement = connection1.prepareStatement(GET_APP)) {

            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);

            OAuthAppDAO AppDAO = new OAuthAppDAO();
            AppDAO.updateOAuthConsumerApp(appName, clientId);
            statement.setString(1, clientId);
            try(ResultSet resultSet = statement.executeQuery()) {
                if(resultSet.next()) {
                    assertEquals(resultSet.getString(1), appName, "Checking whether the table " +
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

        try(Connection connection = getConnection(DB_Name)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

            OAuthAppDAO AppDAO = new OAuthAppDAO();
            assertEquals(AppDAO.getConsumerAppState(clientId), appState, "Checking the APP_STATE for the " +
                    "given CONSUMER_KEY.");
        }
    }

}
