package org.wso2.carbon.identity.oauth.scope.endpoint.impl;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.scope.endpoint.dto.ScopeDTO;
import org.wso2.carbon.identity.oauth.scope.endpoint.dto.ScopeToUpdateDTO;
import org.wso2.carbon.identity.oauth.scope.endpoint.util.ScopeUtils;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeServerException;
import org.wso2.carbon.identity.oauth2.OAuth2ScopeService;
import org.wso2.carbon.identity.oauth2.bean.Scope;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.core.Response;

import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.*;

/**
 * Created by isuri on 10/14/17.
 */
@PowerMockIgnore("javax.*")
@PrepareForTest({ScopeUtils.class,OAuth2ScopeService.class})

public class ScopesApiServiceImplTest {

    @Mock
    private OAuth2ScopeService oAuth2ScopeService;

    @Mock
    private ScopeUtils scopeUtils;

    @BeforeMethod
    public void setUp() throws Exception {
        mockStatic(ScopeUtils.class);
        mockStatic(OAuth2ScopeService.class);
        when(ScopeUtils.getOAuth2ScopeService()).thenReturn(oAuth2ScopeService);
    }

    private final String DESCRIPTION = "JJJJ";
    private final String SCOPENAME = "openId";
    private final String MESSAGE = "Message";
    ArrayList<String> binding = new ArrayList<>(Arrays.asList("scope1", "scope2"));
    private Scope scope = new Scope(SCOPENAME,MESSAGE,binding);

    ScopesApiServiceImpl scopesApiService = new ScopesApiServiceImpl();

    @DataProvider(name = "BuildUpdateScope")
    public Object[][] buildUpdateApplication() {
        String message1 = "Scopeservice1";
        String message2 = "ScopeService2";
        String message3 = "AnyOtherException";

        ScopeToUpdateDTO scopeToUpdateDTO = new ScopeToUpdateDTO();
        scopeToUpdateDTO.setDescription(DESCRIPTION);
        ScopeToUpdateDTO scopeToUpdateDTO1 = new ScopeToUpdateDTO();
        scopeToUpdateDTO1.setDescription(DESCRIPTION);
        ScopeToUpdateDTO scopeToUpdateDTO2 = new ScopeToUpdateDTO();
        scopeToUpdateDTO2.setDescription(DESCRIPTION);
        ScopeToUpdateDTO scopeToUpdateDTO3 = new ScopeToUpdateDTO();
        scopeToUpdateDTO3.setDescription(DESCRIPTION);
        IdentityOAuth2ScopeClientException identityOAuth2ScopeClientException = new IdentityOAuth2ScopeClientException(message1);
        IdentityOAuth2ScopeException oAuth2ScopeException = new IdentityOAuth2ScopeException(message2);
        IdentityOAuth2ScopeServerException identityOAuth2ScopeServerException = new IdentityOAuth2ScopeServerException(message3);
        return new Object[][] {
                {"Scope2",true,null,identityOAuth2ScopeClientException},
                {"Scope3",true,scope, oAuth2ScopeException},
                {"Scope4",true,null,identityOAuth2ScopeServerException}
        };
    }
    @Test(dataProvider = "BuildUpdateScope")
    public void testUpdateScope(String scopeName,boolean isException,Object scopeUpdateDTO,Object exception) throws Exception {

        // Scope scope1 = new Scope(SCOPENAME,DESCRIPTION,binding);
        // String name = "hhhh";

        /*if(isException){
            when(oAuth2ScopeService.updateScope(ScopeUtils.getUpdatedScope((ScopeToUpdateDTO)scopeUpdateDTO , scopeName))).thenThrow((Exception)exception);
        }else {
            when(oAuth2ScopeService.updateScope(ScopeUtils.getUpdatedScope((ScopeToUpdateDTO)scopeUpdateDTO,scopeName))).thenReturn((Scope)scope);
        }
        assertNotEquals((ScopeToUpdateDTO)scopeUpdateDTO,scopeName);
        //assertEquals(scopesApiService.updateScope((ScopeToUpdateDTO)scopeUpdateDTO,scopeName).getStatus(),20);
    }
*/
    }
      /*if (isException) {
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
}*/

    @DataProvider(name = "BuildGetScope")
    public Object[][] buildGetApplication() {
        IdentityOAuth2ScopeClientException scopeClientException = new IdentityOAuth2ScopeClientException("ClientException");
        IdentityOAuth2ScopeServerException scopeServerException = new IdentityOAuth2ScopeServerException("DCRMServerException");
        IdentityOAuth2ScopeException scopeException = new IdentityOAuth2ScopeException("AnyOtherException");
        return new Object[][] {
                {"Scope1",false, null},
                {"Scope2",true, scopeClientException},
                {"Scope3",true, scopeException},
                {"Scope4",true, scopeServerException}
        };
    }
    @Test(dataProvider = "BuildGetScope")
    public void testGetScope(String scopeName, boolean isException, Object exception) throws Exception {
        Scope scope1 = new Scope(SCOPENAME,DESCRIPTION,binding);
        if(isException){
            when(oAuth2ScopeService.getScope(scopeName)).thenThrow((Exception)exception);
        }else {
            when(oAuth2ScopeService.getScope(scopeName)).thenReturn(scope1);
        }

        assertEquals(scopesApiService.getScope(scopeName).getStatus(),200);
    }


    @DataProvider(name = "BuildgetScopes")
    public Object[][] getscopes() {
        return new Object[][]{
                {6565, 39},
                {null, 7664},
                {746, null},
                {null, null}
        };
    }
    @Test(dataProvider = "BuildgetScopes")
    public void testGetScopes(Integer startIndex, Integer count) throws Exception {
        Set<Scope> scope = new HashSet<>();
        // Scope scope1 = new Scope(name1,description,binding);
        mockStatic(ScopeUtils.class);
        when(oAuth2ScopeService.getScopes(startIndex, count)).thenReturn(scope);
        ScopesApiServiceImpl serviceImple = new ScopesApiServiceImpl();
        Response response = serviceImple.getScopes(startIndex, count);
        assertNotNull(response);

    }


    @DataProvider(name = "BuildDeleteScope")
    public Object[][] buildDeleteApplication() {
       IdentityOAuth2ScopeClientException identityOAuth2ScopeClientException = new IdentityOAuth2ScopeClientException("DCRMClientException");
       identityOAuth2ScopeClientException.getErrorDescription();
        //dcrmClientException.setErrorCode("CONFLICT_");
        return new Object[][] {
                {"Scope1", false, identityOAuth2ScopeClientException},
                {"Scope2", true, identityOAuth2ScopeClientException},
        };
    }
    @Test(dataProvider = "BuildDeleteScope")
    public void testDeleteScope(String scopeName, boolean isException, Object exception) throws IdentityOAuth2ScopeException {
        if (isException){
            doThrow((Exception)exception).when(oAuth2ScopeService).deleteScope(scopeName);
        }else{
            doNothing().when(oAuth2ScopeService).deleteScope(scopeName);
        }
        assertEquals(scopesApiService.deleteScope("scope12").getStatus(),200);

    }

    @DataProvider(name = "BuildRegisterScope")
    public Object[][] buildRegisterApplication() {
        ScopeDTO scopeDTO = new ScopeDTO();
        scopeDTO.setName("Scope1");
        ScopeDTO scopeDTO1= new ScopeDTO();
        scopeDTO1.setName("Scope2");
        IdentityOAuth2ScopeClientException dcrmClientException = new IdentityOAuth2ScopeClientException("ClientException");

        return new Object[][] {
                {scopeDTO, false, null},
                {scopeDTO1, true, dcrmClientException}
        };
    }

    @Test(dataProvider = "BuildRegisterScope")
    public void testRegisterScope(Object scopeDTO, boolean isException, Object exception) throws Exception {
        if (isException){
            when(oAuth2ScopeService.registerScope(ScopeUtils.getScope((ScopeDTO)scopeDTO))).thenThrow((Exception)exception);
        }else{
            when(oAuth2ScopeService.registerScope(ScopeUtils.getScope((ScopeDTO)scopeDTO))).thenReturn(scope);
        }
        assertEquals(scopesApiService.registerScope((ScopeDTO)scopeDTO).getStatus(),201);
    }

    @DataProvider(name = "checkisScopeException")
    public Object[][] checkScopeException() {
        String message1 = "Scopeservice1";
        String message2 = "ScopeService2";
        String message3 = "AnyOtherException";

        IdentityOAuth2ScopeClientException identityOAuth2ScopeClientException = new IdentityOAuth2ScopeClientException("hhh");
        IdentityOAuth2ScopeException oAuth2ScopeException = new IdentityOAuth2ScopeException(message2);
        IdentityOAuth2ScopeServerException identityOAuth2ScopeServerException = new IdentityOAuth2ScopeServerException(message3);
        return new Object[][]{
                {"scope", false, scope, identityOAuth2ScopeClientException},
                {"scope70", false, null, oAuth2ScopeException},
                {"scope07", false, null, identityOAuth2ScopeServerException},
                {"scope1", false, null, null}

        };
    }


    @Test(dataProvider = "checkisScopeException")
    public void testIsScopeExists(String scopeName, boolean isException, Object scope, Object exception) throws Exception {

        mockStatic(ScopeUtils.class);
        if (isException) {
            when(oAuth2ScopeService.isScopeExists(scopeName)).thenThrow((Exception) exception);
        } else {

            when(oAuth2ScopeService.isScopeExists(scopeName)).thenReturn(Boolean.TRUE);
        }

        assertEquals(scopesApiService.isScopeExists(scopeName).getStatus(), 404);
    }



    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();

    }

}

