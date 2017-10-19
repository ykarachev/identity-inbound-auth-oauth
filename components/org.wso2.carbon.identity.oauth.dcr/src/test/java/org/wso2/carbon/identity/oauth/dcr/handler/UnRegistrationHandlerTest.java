/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * you may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.dcr.handler;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.dcr.context.DCRMessageContext;
import org.wso2.carbon.identity.oauth.dcr.model.UnregistrationRequest;
import org.wso2.carbon.identity.oauth.dcr.model.UnregistrationResponse;
import org.wso2.carbon.identity.oauth.dcr.service.DCRManagementService;

import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;

@PrepareForTest({UnRegistrationHandler.class, DCRManagementService.class})
public class UnRegistrationHandlerTest extends PowerMockTestCase {

    private UnRegistrationHandler unRegistrationHandler;

    @Mock
    DCRMessageContext mockDcrMessageContext;

    @Mock
    UnregistrationRequest mockUnregistrationRequest;

    @Mock
    DCRManagementService mockDCRManagementService;

    @BeforeMethod
    public void setUp() throws Exception {
        initMocks(this);
        unRegistrationHandler = new UnRegistrationHandler();
    }

    @Test
    public void testHandle() throws Exception {
        when(mockDcrMessageContext.getIdentityRequest()).thenReturn(mockUnregistrationRequest);

        UnregistrationResponse.DCUnregisterResponseBuilder dCUnregisterResponseBuilder =
                new UnregistrationResponse.DCUnregisterResponseBuilder();
        whenNew(UnregistrationResponse.DCUnregisterResponseBuilder.class).withNoArguments().
                thenReturn(dCUnregisterResponseBuilder);

        mockStatic(DCRManagementService.class);
        when (DCRManagementService.getInstance()).thenReturn(mockDCRManagementService);
        mockDCRManagementService.unregisterOAuthApplication(mockUnregistrationRequest.getUserId(),
                mockUnregistrationRequest.getApplicationName(),
                mockUnregistrationRequest.getConsumerKey());

        assertEquals(unRegistrationHandler.handle(mockDcrMessageContext), dCUnregisterResponseBuilder);
    }
}
