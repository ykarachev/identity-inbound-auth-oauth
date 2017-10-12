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

package org.wso2.carbon.identity.oauth.dcr.processor;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;

import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

public class DCRProcessorTest {

    DCRProcessor dcrProcessor;
    IdentityMessageContext mockIdentityMessageContext;
    IdentityRequest mockIdentityRequest;

    @BeforeMethod
    public void setUp() {

        dcrProcessor = new DCRProcessor();
    }

    @Test
    public void testGetCallbackPath() throws Exception {

        mockIdentityMessageContext = mock(IdentityMessageContext.class);
        assertNull(dcrProcessor.getCallbackPath(mockIdentityMessageContext));
    }

    @Test
    public void testGetRelyingPartyId() throws Exception {

        assertNull(dcrProcessor.getRelyingPartyId());
    }

    @Test
    public void testGetRelyingPartyIdWithArg() throws Exception {

        mockIdentityMessageContext = mock(IdentityMessageContext.class);
        assertNull(dcrProcessor.getRelyingPartyId(mockIdentityMessageContext));
    }

    @DataProvider(name = "getHandleStatus")
    public Object[][] getStatus() {
        mockIdentityRequest = mock(IdentityRequest.class);
        return new Object[][] {
                {null, "dummy/identity/dummy", false},
                {mockIdentityRequest, "dummy/identity/dummy", false},
                {mockIdentityRequest, "dummy/identity/register/", true},
                {mockIdentityRequest, "dummy/identity/register/?", true},
                {mockIdentityRequest, "dummy/identity/register/dummy", true}
        };
    }

    @Test(dataProvider = "getHandleStatus")
    public void testCanHandle(IdentityRequest identityRequest, String urlPattern, boolean expected)
            throws Exception {

        when(mockIdentityRequest.getRequestURI()).thenReturn(urlPattern);
        boolean canHandle = dcrProcessor.canHandle(identityRequest);
        assertEquals(canHandle, expected);
    }

}
