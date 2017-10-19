package org.wso2.carbon.identity.oauth.dcr.factory;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationRequest;

import java.io.BufferedReader;
import java.nio.file.Paths;

import org.wso2.carbon.identity.oauth.dcr.model.RegistrationRequestProfile;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MediaType;

import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.powermock.api.mockito.PowerMockito.doAnswer;

import static org.powermock.api.support.membermodification.MemberMatcher.methodsDeclaredIn;
import static org.powermock.api.support.membermodification.MemberModifier.suppress;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.fail;

@PrepareForTest(RegistrationRequestFactory.class)
public class RegistrationRequestFactoryTest extends PowerMockIdentityBaseTest {

    private RegistrationRequestFactory registrationRequestFactory;
    private String dummyDescription = "dummyDescription";
    private String ownerName = "dummyOwnerName";

    @Mock
    HttpServletRequest mockHttpRequest;

    @Mock
    HttpServletResponse mockHttpResponse;

    @Mock
    RegistrationRequest.RegistrationRequestBuilder mockRegistrationRequestBuilder;

    @Mock
    HttpIdentityResponse.HttpIdentityResponseBuilder mockHttpIdentityResponseBuilder;

    @Mock
    BufferedReader mockReader;

    @Mock
    JSONParser jsonParser;

    @BeforeMethod
    private void setUp() {

        registrationRequestFactory = new RegistrationRequestFactory();
    }

    @DataProvider(name = "JSONOBJECTDataProvider")
    public Object[][] getData() {

        JSONArray grantTypes = new JSONArray();
        JSONArray redirectUrls = new JSONArray();
        JSONArray responseTypes = new JSONArray();
        JSONArray scopes = new JSONArray();
        JSONArray contacts = new JSONArray();
        grantTypes.add("dummyGrantType");
        redirectUrls.add("dummyRedirectUrl");
        responseTypes.add("dummyResponseType");
        contacts.add("dummyContact");
        scopes.add("dummyScope");

        String grantType = "dummyGrantType";
        String redirectUrl = "dummyRedirectUrl";
        String responseType = "dummyRedirectUri";
        String clientName = "dummyClientName";
        String scope = "dummyScope";
        String contact = "dummyContact";

        JSONArray emptyGrantTypes = new JSONArray();
        JSONArray emptyRedirectUrls = new JSONArray();
        JSONArray emptyResponseTypes = new JSONArray();
        JSONArray emptyScopes = new JSONArray();
        JSONArray emptyContacts = new JSONArray();
        emptyGrantTypes.add("");
        emptyRedirectUrls.add("");
        emptyResponseTypes.add("");
        emptyScopes.add("");
        emptyContacts.add("");

        JSONArray grantTypeWithInt = new JSONArray();
        JSONArray redirectUrlsWithInt = new JSONArray();
        JSONArray responseTypesWithInt = new JSONArray();
        JSONArray scopesWithInt = new JSONArray();
        JSONArray contactsWithInt = new JSONArray();
        grantTypeWithInt.add(0);
        redirectUrlsWithInt.add(0);
        responseTypesWithInt.add(0);
        contactsWithInt.add(0);
        scopesWithInt.add(0);

        return new Object[][]{
                {grantTypes, redirectUrls, responseTypes, clientName, scopes, contacts, grantTypes},
                {grantType, redirectUrl, responseType, clientName, scope, contact, grantType},
                {emptyGrantTypes, emptyRedirectUrls, emptyResponseTypes, clientName, emptyScopes, emptyContacts,
                        "empty"},
                {0, 0, 0, clientName, 0, 0, "empty"},
                {grantTypeWithInt, redirectUrlsWithInt, responseTypesWithInt, null, scopesWithInt, contactsWithInt,
                        "empty"}
        };
    }

    @Test(dataProvider = "JSONOBJECTDataProvider")
    public void testCreate(Object grantType, Object redirectUrl, Object responseType, String clientName, Object
            scope, Object contact, Object expected) throws Exception {

        JSONObject jsonObject = new JSONObject();
        jsonObject.put(RegistrationRequest.RegisterRequestConstant.GRANT_TYPES, grantType);
        jsonObject.put(RegistrationRequest.RegisterRequestConstant.REDIRECT_URIS, redirectUrl);
        jsonObject.put(RegistrationRequest.RegisterRequestConstant.RESPONSE_TYPES, responseType);
        jsonObject.put(RegistrationRequest.RegisterRequestConstant.CLIENT_NAME, clientName);
        jsonObject.put(RegistrationRequest.RegisterRequestConstant.SCOPE, scope);
        jsonObject.put(RegistrationRequest.RegisterRequestConstant.CONTACTS, contact);

        RegistrationRequestProfile registrationRequestProfile = new RegistrationRequestProfile();

        whenNew(RegistrationRequestProfile.class).withNoArguments().thenReturn(registrationRequestProfile);

        suppress(methodsDeclaredIn(HttpIdentityRequestFactory.class));

        when(mockHttpRequest.getReader()).thenReturn(mockReader);
        whenNew(JSONParser.class).withNoArguments().thenReturn(jsonParser);

        when(jsonParser.parse(mockReader)).thenReturn(jsonObject);

        String carbonHome = Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(ownerName);

        registrationRequestFactory.create(mockRegistrationRequestBuilder, mockHttpRequest, mockHttpResponse);

        if (clientName != null) {
            assertEquals(registrationRequestProfile.getClientName(), clientName);
        }

        if (!expected.equals("empty")) {
            if (expected instanceof String) {
                assertEquals(registrationRequestProfile.getGrantTypes().get(0), grantType);
                assertEquals(registrationRequestProfile.getRedirectUris().get(0), redirectUrl);
                assertEquals(registrationRequestProfile.getContacts().get(0), contact);
                assertEquals(registrationRequestProfile.getScopes().get(0), scope);
                assertEquals(registrationRequestProfile.getResponseTypes().get(0), responseType);
            } else {
                assertEquals(registrationRequestProfile.getGrantTypes(), grantType);
                assertEquals(registrationRequestProfile.getRedirectUris(), redirectUrl);
                assertEquals(registrationRequestProfile.getContacts(), contact);
                assertEquals(registrationRequestProfile.getScopes(), scope);
                assertEquals(registrationRequestProfile.getResponseTypes(), responseType);
            }

        }
        assertEquals(registrationRequestProfile.getOwner(), ownerName);
    }

    @Test
    public void testCreateWithEmptyRedirectUri() throws Exception {

        String grantType = "implicit";
        int redirectUrl = 0;
        JSONObject jsonObject = new JSONObject();

        jsonObject.put(RegistrationRequest.RegisterRequestConstant.GRANT_TYPES, grantType);
        jsonObject.put(RegistrationRequest.RegisterRequestConstant.REDIRECT_URIS, redirectUrl);

        RegistrationRequestProfile registrationRequestProfile = new RegistrationRequestProfile();

        whenNew(RegistrationRequestProfile.class).withNoArguments().thenReturn(registrationRequestProfile);

        suppress(methodsDeclaredIn(HttpIdentityRequestFactory.class));

        when(mockHttpRequest.getReader()).thenReturn(mockReader);
        whenNew(JSONParser.class).withNoArguments().thenReturn(jsonParser);

        when(jsonParser.parse(mockReader)).thenReturn(jsonObject);

        String carbonHome = Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(ownerName);

        try {
            registrationRequestFactory.create(mockRegistrationRequestBuilder, mockHttpRequest, mockHttpResponse);
            fail();
        } catch (FrameworkClientException ex) {
            assertEquals(ex.getMessage(), "RedirectUris property must have at least one URI value.");
        }
    }

    @Test
    public void testHandleException() throws Exception {

        whenNew(HttpIdentityResponse.HttpIdentityResponseBuilder.class).withNoArguments().thenReturn
                (mockHttpIdentityResponseBuilder);

        final Integer[] statusCode = new Integer[1];
        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                statusCode[0] = (Integer) invocation.getArguments()[0];
                return null;
            }
        }).when(mockHttpIdentityResponseBuilder).setStatusCode(anyInt());

        final String[] header = new String[2];
        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                header[1] = (String) invocation.getArguments()[1];
                return null;
            }
        }).when(mockHttpIdentityResponseBuilder).addHeader(anyString(), anyString());

        FrameworkClientException exception = mock(FrameworkClientException.class);
        when(exception.getMessage()).thenReturn(dummyDescription);
        registrationRequestFactory.handleException(exception, mockHttpRequest, mockHttpResponse);

        assertEquals(header[1], MediaType.APPLICATION_JSON);
        assertEquals((int) statusCode[0], HttpServletResponse.SC_BAD_REQUEST);
    }

    @Test
    public void testGenerateErrorResponse() throws Exception {

        String dummyError = "dummyError";

        JSONObject jsonObject = registrationRequestFactory.generateErrorResponse(dummyError, dummyDescription);
        assertEquals(jsonObject.get("error"), dummyError);
        assertEquals(jsonObject.get("error_description"), dummyDescription);
    }
}