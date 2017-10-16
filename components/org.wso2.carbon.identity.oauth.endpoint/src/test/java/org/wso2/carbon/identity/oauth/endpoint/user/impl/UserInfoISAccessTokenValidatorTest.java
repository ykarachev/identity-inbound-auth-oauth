package org.wso2.carbon.identity.oauth.endpoint.user.impl;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;

import java.util.Scanner;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.HttpHeaders;

import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;

@PrepareForTest(UserInforRequestDefaultValidator.class)
public class UserInfoISAccessTokenValidatorTest extends PowerMockTestCase {

    @Mock
    private HttpServletRequest httpServletRequest;
    @Mock
    private Scanner scanner;
    private UserInforRequestDefaultValidator userInforRequestDefaultValidator;
    private final String BASIC_AUTH_HEADER = "Bearer ZWx1c3VhcmlvOnlsYWNsYXZl";


    @BeforeClass
    public void setup() {
        userInforRequestDefaultValidator = new UserInforRequestDefaultValidator();
    }

    @Test
    public void testValidateToken() throws Exception {
        prepareHttpServletRequest(BASIC_AUTH_HEADER, null);
        assertEquals(BASIC_AUTH_HEADER.split(" ")[1], userInforRequestDefaultValidator.validateRequest
                (httpServletRequest));
    }

    @DataProvider
    public Object[][] getInvalidAuthorizations() {
        return new Object[][]{
                {"1234567890wertyuhjik", null},
                {"Bearer", null},
                {null, "application/text"},
                {null, ""},
        };
    }

    @Test(dataProvider = "getInvalidAuthorizations", expectedExceptions = UserInfoEndpointException.class)
    public void testValidateTokenInvalidAuthorization(String authorization, String contentType) throws Exception {
        prepareHttpServletRequest(authorization, contentType);
        userInforRequestDefaultValidator.validateRequest(httpServletRequest);
    }

    private void prepareHttpServletRequest(String authorization, String contentType) {
        when(httpServletRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(authorization);
        when(httpServletRequest.getHeader(HttpHeaders.CONTENT_TYPE)).thenReturn(contentType);
    }
}