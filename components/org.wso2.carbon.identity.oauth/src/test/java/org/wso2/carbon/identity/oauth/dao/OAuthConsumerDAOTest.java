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
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.Parameters;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;

/*
 * Unit tests for OAuthConsumerDAO
 */
@PrepareForTest({IdentityDatabaseUtil.class, OAuthServerConfiguration.class, OAuthConsumerDAO.class})
public class OAuthConsumerDAOTest extends TestOAuthDAOBase {

    private static final String clientId = "ca19a540f544777860e44e75f605d927";
    private static final String secret = "87n9a540f544777860e44e75f605d435";
    private static final String appName = "myApp";
    private static final String username = "user1";
    private static final String appState = "ACTIVE";
    private static final String callback = "http://localhost:8080/redirect";
    private static final String acc_Token = "fakeAccToken";
    private static final String acc_Token_Secret = "fakeTokenSecret";
    private static final String req_Token = "fakeReqToken";
    private static final String req_Token_Secret = "fakeReqToken";
    private static final String scope = "openid";
    private static final String authz_user = "fakeAuthzUser";
    private static final String oauth_verifier = "fakeOauthVerifier";
    private static final String newSecret = "a459a540f544777860e44e75f605d875";
    private static final String DB_Name = "testDB";

    @Mock
    private OAuthServerConfiguration mockedServerConfig;

    @Mock
    private Parameters mockedParameters;

    @BeforeClass
    public void setUp() throws Exception {

        initiateH2Base(DB_Name, getFilePath("h2.sql"));

        int consumer_ID = createBase(clientId, secret, username, appName, callback, appState);
        createAccTokenTable(consumer_ID, acc_Token, acc_Token_Secret, scope, authz_user);
        createReqTokenTable(consumer_ID, req_Token, req_Token_Secret, scope, callback, oauth_verifier, authz_user);
    }

    @Test
    public void testGetOAuthConsumerSecret() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try(Connection connection1 = getConnection(DB_Name)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            assertEquals(consumerDAO.getOAuthConsumerSecret(clientId), secret);
        }
    }

    @Test
    public void testUpdateSecretKey() throws Exception {

        String GET_SECRET = "SELECT CONSUMER_SECRET FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY=?";
        String con_Secret = null;

        PreparedStatement statement = null;
        ResultSet resultSet = null;

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try(Connection connection = getConnection(DB_Name)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            consumerDAO.updateSecretKey(clientId, newSecret);

            try {
                statement = connection.prepareStatement(GET_SECRET);
                statement.setString(1, clientId);
                resultSet = statement.executeQuery();
                if(resultSet.next()) {
                    con_Secret = resultSet.getString(1);
                }
            } finally {
                IdentityDatabaseUtil.closeAllConnections(connection, resultSet, statement);
            }
            assertEquals(con_Secret, newSecret, "Checking whether the passed value is set to the " +
                    " CONSUMER_SECRET.");
        }

    }

    @Test
    public void testGetAuthenticatedUsername() throws Exception {

        mockStatic(IdentityDatabaseUtil.class);

        try(Connection connection2 = getConnection(DB_Name)) {
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection2);

            mockStatic(OAuthServerConfiguration.class);
            when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
            PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
            when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            assertEquals(consumerDAO.getAuthenticatedUsername(clientId, secret), username);
        }
    }

    @DataProvider(name = "provideTokens")
    public Object[][] provideTokens() throws Exception {
        return new Object[][]{
                {acc_Token, true, acc_Token_Secret},
                {req_Token, false, req_Token_Secret}
        };
    }

    @Test(dataProvider = "provideTokens")
    public void testGetOAuthTokenSecret(String token, Boolean isAccessToken, String expected) throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try(Connection connection3 = getConnection(DB_Name)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection3);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            assertEquals(consumerDAO.getOAuthTokenSecret(token, isAccessToken), expected);
        }
    }

    @Test
    public void testGetRequestToken() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        whenNew(Parameters.class).withNoArguments().thenReturn(mockedParameters);

        try(Connection connection3 = getConnection(DB_Name)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection3);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            assertEquals(consumerDAO.getRequestToken(req_Token), mockedParameters);
        }
    }

    @Test
    public void testCreateOAuthRequestToken_01() throws Exception {

        String GET_ID = "SELECT ID FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY=?";
        String REQ_ID = "SELECT REQUEST_TOKEN FROM IDN_OAUTH1A_REQUEST_TOKEN WHERE CONSUMER_KEY_ID=?";
        Integer ID = null;
        String REQ_TOKEN = null;
        PreparedStatement statement1 = null;
        PreparedStatement statement2 = null;

        ResultSet resultSet1 = null;
        ResultSet resultSet2 = null;

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try(Connection connection3 = getConnection(DB_Name)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection3);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            consumerDAO.createOAuthRequestToken(clientId, acc_Token, secret, callback, scope);

            try {
                statement1 = connection3.prepareStatement(GET_ID);
                statement1.setString(1, clientId);
                resultSet1 = statement1.executeQuery();
                if(resultSet1.next()) {
                     ID = resultSet1.getInt(1);
                }

                statement2 = connection3.prepareStatement(REQ_ID);
                statement2.setInt(1, ID);
                resultSet2 = statement2.executeQuery();
                if(resultSet2.next()){
                    REQ_TOKEN = resultSet2.getString(1);
                }
            } finally {
                IdentityDatabaseUtil.closeAllConnections(connection3, resultSet1, statement1);
            }

            assertEquals(REQ_TOKEN, req_Token, "Checking whether the passed req_Token is set to the " +
                    "REQ_TOKEN.");
        }
    }

    @Test
    public void testCreateOAuthRequestToken_02() throws Exception {

        String callback_URL = null;
        String c_Id = "fakeClientId";
        String ac_Token = "fakeAccToken";
        String secretFake = "fakeSecret";
        String fakeScope = "fakeScope";

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try(Connection connection3 = getConnection(DB_Name)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection3);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            consumerDAO.createOAuthRequestToken(c_Id, ac_Token, secretFake, callback_URL, fakeScope);
        }
    }

    @Test
    public void testAuthorizeOAuthToken() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        whenNew(Parameters.class).withNoArguments().thenReturn(mockedParameters);

        try(Connection connection3 = getConnection(DB_Name)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection3);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            assertEquals(consumerDAO.authorizeOAuthToken(req_Token, username, oauth_verifier), mockedParameters);
        }
    }

    @Test
    public void testValidateAccessToken() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(processor);

        try(Connection connection = getConnection(DB_Name)) {
            mockStatic(IdentityDatabaseUtil.class);
            when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

            OAuthConsumerDAO consumerDAO = new OAuthConsumerDAO();
            assertEquals(consumerDAO.validateAccessToken(clientId, acc_Token, scope), authz_user);
        }
    }

}
