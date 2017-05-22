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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.config;

import junit.framework.TestCase;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;

import java.lang.reflect.Field;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;

/**
 * Test case for OAuthServerConfiguration.
 */
public class OAuthServerConfigurationTest extends TestCase {

    public void setUp() throws IllegalAccessException, NoSuchFieldException, URISyntaxException {
        System.setProperty(CarbonBaseConstants.CARBON_HOME, ".");

        //Reset the singleton objects
        Field parserField = IdentityConfigParser.class.getDeclaredField("parser");
        parserField.setAccessible(true);
        parserField.set(null, null);


        Field instanceField = OAuthServerConfiguration.class.getDeclaredField("instance");
        instanceField.setAccessible(true);
        instanceField.set(null, null);
    }

    public void testAmrInternalToExternalMap() {
        IdentityConfigParser
                .getInstance(OAuthServerConfigurationTest.class.getResource("identity-with-amr-map.xml").getPath().toString());
        Map<String, List<String>> amrMap = OAuthServerConfiguration.getInstance().getAmrInternalToExternalMap();
        assertNotNull(amrMap);
        assertEquals("tstauth", amrMap.get("test_auth_step").get(0));
    }

    public void testAmrInternalToExternalMap_WithNoAmrMap() {
        IdentityConfigParser
                .getInstance(OAuthServerConfigurationTest.class.getResource("identity-default.xml").getPath().toString());
        Map<String, List<String>> amrMap = OAuthServerConfiguration.getInstance().getAmrInternalToExternalMap();
        assertNotNull(amrMap);
        assertNull(amrMap.get("test_auth_step"));
    }

    public void testAmrInternalToExternalMap_WithNullAmr() {
        IdentityConfigParser
                .getInstance(OAuthServerConfigurationTest.class.getResource("identity-with-amr-map.xml").getPath().toString());
        Map<String, List<String>> amrMap = OAuthServerConfiguration.getInstance().getAmrInternalToExternalMap();
        assertNotNull(amrMap);
        assertNotNull(amrMap.get("test_auth_step_null"));
        assertTrue(amrMap.get("test_auth_step_null").isEmpty());
    }
}