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

package org.wso2.carbon.identity.oauth2.test.utils;


import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.tomcat.jndi.CarbonJavaURLContextFactory;

import java.nio.file.Paths;
import java.util.Properties;

import javax.naming.InitialContext;
import javax.naming.NamingException;

import static org.testng.Assert.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;
import static org.wso2.carbon.identity.oauth.dao.TestOAuthDAOBase.getDatasource;

public class CommonTestUtils {

    public static final String JDBC_SUBCONTEXT = "jdbc";

    private CommonTestUtils() {
    }

    public static void testSingleton(Object instance, Object anotherInstance) {
        assertNotNull(instance);
        assertNotNull(anotherInstance);
        assertEquals(instance, anotherInstance);
    }

    public static void initPrivilegedCarbonContext(String tenantDomain,
                                                   int tenantID,
                                                   String userName) throws Exception {
        String carbonHome = Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(tenantID);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(userName);
    }

    public static void initPrivilegedCarbonContext() throws Exception {
        String tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        int tenantID = MultitenantConstants.SUPER_TENANT_ID;
        String userName = "testUser";

        initPrivilegedCarbonContext(tenantDomain, tenantID, userName);
    }

    public static void setOAuthServerConfigurationProperties(String carbonHome) {
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
        System.setProperty(TestConstants.CARBON_PROTOCOL, TestConstants.CARBON_PROTOCOL_HTTPS);
        System.setProperty(TestConstants.CARBON_HOST, TestConstants.CARBON_HOST_LOCALHOST);
        System.setProperty(TestConstants.CARBON_MANAGEMENT_PORT, TestConstants.CARBON_DEFAULT_HTTPS_PORT);
    }

    public static void populateInitialContext(String dbName) throws NamingException {
        Properties properties = new Properties();
        properties.put(TestConstants.JAVA_NAMING_FACTORY_INITIAL,
                       new CarbonJavaURLContextFactory().getClass().getCanonicalName());
        InitialContext initialContext = new InitialContext(properties);
        initialContext.createSubcontext(JDBC_SUBCONTEXT);
        initialContext.bind(dbName, getDatasource(dbName));
    }

}
