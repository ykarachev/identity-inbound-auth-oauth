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

package org.wso2.carbon.identity.oauth.scope.endpoint.util;


import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.scope.endpoint.dto.ErrorDTO;
import org.wso2.carbon.identity.oauth.scope.endpoint.dto.ScopeDTO;
import org.wso2.carbon.identity.oauth.scope.endpoint.dto.ScopeToUpdateDTO;
import org.wso2.carbon.identity.oauth2.bean.Scope;

import java.util.ArrayList;
import java.util.Arrays;

import static org.mockito.Mockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;


public class ScopeUtilsTest {


    @Test(description = "Testing getErrorDTO")
    public void testGetErrorDTO() throws Exception {

        ErrorDTO errorDTOexpected = new ErrorDTO();
        errorDTOexpected.setCode("AJYRKLWB68NSB9");
        errorDTOexpected.setMessage("Lifecycle exception occurred");
        errorDTOexpected.setDescription("Error occurred while changing lifecycle state");

        ErrorDTO errorDTO1 = ScopeUtils.getErrorDTO("Lifecycle exception occurred", "AJYRKLWB68NSB9", "Error occurred while changing lifecycle state");
        Assert.assertEquals(errorDTO1.getCode(), errorDTOexpected.getCode());
        Assert.assertEquals(errorDTO1.getMessage(), errorDTOexpected.getMessage());
        Assert.assertEquals(errorDTO1.getDescription(), errorDTOexpected.getDescription());

    }

    @Test(description = "Testing getScope")
    public void testGetScope() throws Exception {

        ScopeDTO scopeDTO = mock(ScopeDTO.class);
        ArrayList<String> scope = new ArrayList<>();

        when(scopeDTO.getBindings()).thenReturn(scope);
        when(scopeDTO.getName()).thenReturn("Lifecycle exception occurred");
        when(scopeDTO.getDescription()).thenReturn("Error occurred while changing lifecycle state");

        Scope scopeexpected = new Scope("Error occurred while changing lifecycle state", "Lifecycle exception occurred", new ArrayList<String>(Arrays.asList("scope1", "scope2")));
        scopeexpected.setName("Lifecycle exception occurred");
        scopeexpected.setDescription("Error occurred while changing lifecycle state");
        scopeexpected.setBindings(scope);

        Scope scope1 = ScopeUtils.getScope(scopeDTO);
        Assert.assertEquals(scope1.getName(), scopeexpected.getName());
        Assert.assertEquals(scope1.getDescription(), scopeexpected.getDescription());
        Assert.assertEquals(scope1.getBindings(), scopeexpected.getBindings());

    }

    @Test(description = "Testing getScopeDTO")
    public void testGetScopeDTO() throws Exception {

        Scope scope = mock(Scope.class);
        when(scope.getBindings()).thenReturn(new ArrayList<String>());
        when(scope.getDescription()).thenReturn("Lifecycle exception occurred");
        when(scope.getName()).thenReturn("Error occurred while changing lifecycle state");

        ScopeDTO scopeDTOexpected = new ScopeDTO();
        scopeDTOexpected.setBindings(new ArrayList<String>());
        scopeDTOexpected.setDescription("Lifecycle exception occurred");
        scopeDTOexpected.setName("Error occurred while changing lifecycle state");

        ScopeDTO scopeDTO1 = ScopeUtils.getScopeDTO(scope);
        Assert.assertEquals(scopeDTO1.getBindings(), scopeDTOexpected.getBindings());
        Assert.assertEquals(scopeDTO1.getDescription(), scopeDTOexpected.getDescription());
        Assert.assertEquals(scopeDTO1.getName(), scopeDTOexpected.getName());

    }

    @Test(description = "Testing getUpdateScope")
    public void testGetUpdatedScope() throws Exception {

        ScopeToUpdateDTO scopeToUpdateDTO = mock(ScopeToUpdateDTO.class);
        ArrayList<String> scope = new ArrayList<>(Arrays.asList("scope1", "scope2"));
        when(scopeToUpdateDTO.getDescription()).thenReturn("Error occurred while changing lifecycle state");
        when(scopeToUpdateDTO.getBindings()).thenReturn(scope);

        Scope scopeexpected = new Scope("openid", "Error occurred while changing lifecycle state", scope);
        scopeexpected.setDescription("Error occurred while changing lifecycle state");
        scopeexpected.setBindings(scope);
        ScopeToUpdateDTO sc = new ScopeToUpdateDTO();

        Scope scope1 = ScopeUtils.getUpdatedScope(scopeToUpdateDTO, "openid");
        Assert.assertEquals(scope1.getDescription(), scopeexpected.getDescription());
        Assert.assertEquals(scope1.getBindings(), scopeexpected.getBindings());

    }

    @Test
    public void testGetScopeDTOs() throws Exception {


    }

}