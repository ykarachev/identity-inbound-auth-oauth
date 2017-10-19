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

package org.wso2.carbon.identity.oauth2.internal;

import org.apache.commons.dbcp.BasicDataSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthConsumerDAO;
import org.wso2.carbon.identity.oauth.dao.TestOAuthDAOBase;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;

import java.sql.Connection;
import java.sql.SQLException;

import static org.mockito.Matchers.anyString;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.oauth2.dao.util.DAOUtils.getFilePath;

/**
 * Test class for OAuthApplicationMgtListener test cases.
 */
@PrepareForTest({OAuth2ServiceComponentHolder.class, OAuthServerConfiguration.class, IdentityDatabaseUtil.class})
public class OAuthApplicationMgtListenerTest extends TestOAuthDAOBase {

    private static final String CLIENT_ID = "ca19a540f544777860e44e75f605d927";
    private static final String SECRET = "87n9a540f544777860e44e75f605d435";
    private static final String APP_NAME = "myApp";
    private static final String USER_NAME = "user1";
    private static final String APP_STATE = "ACTIVE";
    private static final String CALLBACK = "http://localhost:8080/redirect";
    private static final String DB_NAME = "testDB";

    public static final String OAUTH2 = "oauth2";
    private static final String oauthConsumerSecret = "oauthConsumerSecret";
    private String tenantDomain = "carbon.super";
    Connection connection;

    @InjectMocks
    OAuthApplicationMgtListener oAuthApplicationMgtListener = new OAuthApplicationMgtListener();

    @Mock
    private ApplicationManagementService mockAppMgtService;
    @Mock
    private OAuthConsumerDAO mockDAO;
    @Mock
    private OAuthServerConfiguration mockOauthServicerConfig;

    @BeforeClass
    public void setUp() throws Exception {
//        connection = setUpDatabaseConnection();

                         initiateH2Base(DB_NAME, getFilePath("h2.sql"));
                    //createBase(CLIENT_ID, SECRET, USER_NAME, APP_NAME, CALLBACK);

    }


    @BeforeMethod
    public void setUpBeforeMethod() throws Exception {

        initMocks(this);
        mockStatic(OAuth2ServiceComponentHolder.class);
        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

        PlainTextPersistenceProcessor processor = new PlainTextPersistenceProcessor();
        when(mockOauthServicerConfig.getPersistenceProcessor()).thenReturn(processor);

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockOauthServicerConfig);


        when(OAuth2ServiceComponentHolder.getApplicationMgtService()).thenReturn(mockAppMgtService);
        whenNew(OAuthConsumerDAO.class).withNoArguments().thenReturn(mockDAO);
        when(mockDAO.getOAuthConsumerSecret(anyString())).thenReturn("consumerSecret");

    }

    @AfterTest
    public void tearDown() throws SQLException {

        if (connection != null && !connection.isClosed()) {
            connection.close();
        }
    }

    public Connection setUpDatabaseConnection() throws Exception {

        BasicDataSource dataSource = new BasicDataSource();

        dataSource.setDriverClassName("org.h2.Driver");
        dataSource.setUsername("username");
        dataSource.setPassword("password");
        dataSource.setUrl("jdbc:h2:mem:test");

        Connection connection = dataSource.getConnection();
        connection.createStatement().executeUpdate("RUNSCRIPT FROM 'src/test/resources/dbscripts/h2.sql'");

        return connection;
    }

    public ServiceProvider createServiceProvider(int appId, Boolean hasAuthConfig, Boolean hasRequestConfig,
                                                 String authType,
                                                 String propName) {

        ServiceProvider serviceProvider = new ServiceProvider();
        serviceProvider.setApplicationID(appId);

        if (hasAuthConfig) {
            InboundAuthenticationConfig inboundAuthenticationConfig = new InboundAuthenticationConfig();
            if (hasRequestConfig) {
                InboundAuthenticationRequestConfig[] requestConfig = new InboundAuthenticationRequestConfig[1];
                requestConfig[0] = new InboundAuthenticationRequestConfig();
                requestConfig[0].setInboundAuthType(authType);
                requestConfig[0].setInboundAuthKey("authKey");
                Property[] properties = new Property[1];
                properties[0] = new Property();
                properties[0].setName(propName);
                requestConfig[0].setProperties(properties);
                inboundAuthenticationConfig.setInboundAuthenticationRequestConfigs(requestConfig);
            } else {
                inboundAuthenticationConfig.setInboundAuthenticationRequestConfigs(null);
            }

            serviceProvider.setInboundAuthenticationConfig(inboundAuthenticationConfig);
        }

        return serviceProvider;
    }


    @Test
    public void testGetDefaultOrderId() {

        int result = oAuthApplicationMgtListener.getDefaultOrderId();
        assertEquals(result, 11);
    }

    @Test(dataProvider = "SPConfigData")
    public void testDoPreUpdateApplication(Boolean hasAuthConfig, Boolean hasRequestConfig, String authType,
                                           String propName)
            throws IdentityApplicationManagementException {


        ServiceProvider serviceProvider = createServiceProvider(1, hasAuthConfig, hasRequestConfig, authType,
                propName);

        ServiceProvider serviceProvider2 = new ServiceProvider();
        serviceProvider.setApplicationID(1);
        serviceProvider.setSaasApp(true);
        when(mockAppMgtService.getServiceProvider(serviceProvider.getApplicationID())).thenReturn(serviceProvider2);

        Boolean result =
                oAuthApplicationMgtListener.doPreUpdateApplication(serviceProvider, "carbon.super", "userName");
        assertTrue(result);
    }

    @DataProvider(name = "SPConfigData")
    public Object[][] getSPConfigData() {


        return new Object[][]{
                {true, true, OAUTH2, "oauthConsumerSecret"},
                {true, false, null, null},
                {true, true, "otherAuthType", "otherPropName"},
                {true, true, OAUTH2, "otherPropName"},
                {false, false, null, null},

        };
    }

    @Test
    public void doPostGetServiceProvider() throws Exception {

        ServiceProvider serviceProvider1 = createServiceProvider(1, true, true, OAUTH2, "oauthConsumerSecret");
        Boolean result = oAuthApplicationMgtListener.doPostGetServiceProvider(serviceProvider1, "spName", tenantDomain);
        assertTrue(result);
    }


}
