/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.oauth2.dcr.endpoint.impl;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.*;
import org.wso2.carbon.identity.oauth.dcr.bean.Application;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMClientException;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMException;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMServerException;
import org.wso2.carbon.identity.oauth.dcr.service.DCRMService;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.RegistrationRequestDTO;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.UpdateRequestDTO;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.util.DCRMUtils;

import java.util.ArrayList;
import java.util.List;

import static org.powermock.api.mockito.PowerMockito.*;
import static org.powermock.api.mockito.PowerMockito.when;

@PrepareForTest({DCRMUtils.class, DCRMService.class})
@PowerMockIgnore("javax.*")
public class RegisterApiServiceImplTest {
    private Application application = new Application();
    private List<String> redirectUris = new ArrayList<>();
    private RegisterApiServiceImpl registerApiService = new RegisterApiServiceImpl();
    @Mock
    private DCRMUtils dcrmUtils;

    @Mock
    private DCRMService dcrmService;

    @BeforeMethod
    public void setUp() throws Exception {
        redirectUris.add("https://op.certification.openid.net:60845/authz_cb");
        application.setClient_name("Application");
        application.setClient_id("N2QqQluzQuL5X6CtM3KZwqzLQhUa");
        application.setClient_secret("4AXWrN88aEfMvq2h_G0dN05KRsUa");
        application.setRedirect_uris(redirectUris);
        mockStatic(DCRMUtils.class);
        mockStatic(DCRMService.class);
        when(DCRMUtils.getOAuth2DCRMService()).thenReturn(dcrmService);
    }

    @DataProvider(name = "BuildDeleteApplication")
    public Object[][] buildDeleteApplication() {
        DCRMClientException dcrmClientException = new DCRMClientException("DCRMClientException");
        dcrmClientException.setErrorCode("CONFLICT_");
        return new Object[][] {
                {"N2QqQluzQuL5X6CtM3KZwqzLQhUq", false, null},
                {"N2QqQluzQuL5X6CtM3KZwqzLQyys", true, dcrmClientException},
        };
    }

    @Test(dataProvider ="BuildDeleteApplication")
    public void testDeleteApplication(String clientId, boolean isException, Object exception) throws DCRMException {
        if (isException) {
            doThrow((Exception)exception).when(dcrmService).deleteApplication(clientId);
        } else {
            doNothing().when(dcrmService).deleteApplication(clientId);
        }
        Assert.assertEquals(registerApiService.deleteApplication("N2QqQluzQuL5X6CtM3KZwqzLQhUa").getStatus(),204);
    }

    @DataProvider(name = "BuildGetApplication")
    public Object[][] buildGetApplication() {
        DCRMClientException dcrmClientException = new DCRMClientException("DCRMClientException");
        DCRMServerException dcrmServerException = new DCRMServerException("DCRMServerException");
        DCRMException dcrmException = new DCRMException("AnyOtherException");
        return new Object[][] {
                {"N2QqQluzQuL5X6CtM3KZwqzLQhUl", application, false, null},
                {"N2QqQluzQuL5X6CtM3KZwqzLQyyy", null, true, dcrmClientException},
                {"N2QqQluzQuL5X6CtM3KZwqzLQxxx", null, true, dcrmException},
                {"N2QqQluzQuL5X6CtM3KZwqzLQhUa", null, true, dcrmServerException}
        };
    }

    @Test(dataProvider = "BuildGetApplication")
    public void testGetApplication(String clientId, Object app, boolean isException, Object exception) throws DCRMException {
        if (isException) {
           when(dcrmService.getApplication(clientId)).thenThrow((DCRMException)exception);
        } else {
            when(dcrmService.getApplication(clientId)).thenReturn((Application) app);
        }
        Assert.assertEquals(registerApiService.getApplication(clientId).getStatus(),200);
    }

    @DataProvider(name = "BuildRegisterApplication")
    public Object[][] buildRegisterApplication() {
        RegistrationRequestDTO registrationRequestDTO1 = new RegistrationRequestDTO();
        registrationRequestDTO1.setClientName("Client1");
        RegistrationRequestDTO registrationRequestDTO2 = new RegistrationRequestDTO();
        registrationRequestDTO2.setClientName("Client2");
        DCRMClientException dcrmClientException = new DCRMClientException("DCRMClientException");

        return new Object[][] {
                {registrationRequestDTO1, false, null},
                {registrationRequestDTO2, true, dcrmClientException}
        };
    }

    @Test(dataProvider ="BuildRegisterApplication" )
    public void testRegisterApplication(Object registrationRequestDTO, boolean isException, Object exception) throws Exception {


        if (isException) {
            when(dcrmService.registerApplication
                    (DCRMUtils.getApplicationRegistrationRequest((RegistrationRequestDTO) registrationRequestDTO)))
                    .thenThrow((Exception)exception);
        } else {
            when(dcrmService.registerApplication
                    (DCRMUtils.getApplicationRegistrationRequest((RegistrationRequestDTO) registrationRequestDTO)))
                    .thenReturn(application);
        }

        Assert.assertEquals(registerApiService.registerApplication((RegistrationRequestDTO) registrationRequestDTO)
                .getStatus(),201);
    }

    @DataProvider(name = "BuildUpdateApplication")
    public Object[][] buildUpdateApplication() {
        UpdateRequestDTO updateRequestDTO1 = new UpdateRequestDTO();
        updateRequestDTO1.setClientName("Client1");
        UpdateRequestDTO updateRequestDTO2 = new UpdateRequestDTO();
        updateRequestDTO2.setClientName("Client2");
        UpdateRequestDTO updateRequestDTO3 = new UpdateRequestDTO();
        updateRequestDTO3.setClientName("Client3");
        UpdateRequestDTO updateRequestDTO4 = new UpdateRequestDTO();
        updateRequestDTO4.setClientName("Client4");
        DCRMClientException dcrmClientException = new DCRMClientException("DCRMClientException");
        DCRMServerException dcrmServerException = new DCRMServerException("DCRMServerException");
        DCRMException dcrmException = new DCRMException("AnyOtherException");
        return new Object[][] {
                {"clientID1", updateRequestDTO1, false, null},
                {"clientID2", updateRequestDTO2, true, dcrmClientException},
                {"clientID3", updateRequestDTO3, true, dcrmException},
                {"clientID4", updateRequestDTO4, true, dcrmServerException}
        };
    }

    @Test(dataProvider ="BuildUpdateApplication")
    public void testUpdateApplication(String clientID,Object updateRequestDTO, boolean isException, Object exception) throws Exception {
        if (isException) {
            when(dcrmService.updateApplication
                    (DCRMUtils.getApplicationUpdateRequest((UpdateRequestDTO)updateRequestDTO),clientID))
                    .thenThrow((Exception)exception);
        } else {
            when(dcrmService.updateApplication
                    (DCRMUtils.getApplicationUpdateRequest((UpdateRequestDTO)updateRequestDTO),clientID))
                    .thenReturn(application);
        }
        Assert.assertEquals(registerApiService.updateApplication((UpdateRequestDTO)
                updateRequestDTO,clientID).getStatus(),200);
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();

    }

}
