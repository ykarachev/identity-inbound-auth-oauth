package org.wso2.carbon.identity.oauth2.token.handlers.grant;

import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;

import java.util.Arrays;

import static junit.framework.TestCase.assertEquals;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;

/**
 * Test class for RefreshGrantHandler test cases.
 */
@PrepareForTest({OAuthServerConfiguration.class, TokenMgtDAO.class, AbstractAuthorizationGrantHandler.class,
        IdentityUtil.class})
public class RefreshGrantHandlerTest extends PowerMockTestCase {

    private String accessToken = "accessToken";
    private String refreshToken = "refreshToken";
    private RefreshGrantHandler refreshGrantHandler;

    @Mock
    private TokenMgtDAO mockTokenMgtDAO;
    @Mock
    private OAuthServerConfiguration mockOAuthServerConfiguration;

    @BeforeMethod
    public void setUp() throws Exception {

        initMocks(this);
        mockStatic(OAuthServerConfiguration.class);
        mockStatic(IdentityUtil.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockOAuthServerConfiguration);
        spy(OAuthCache.class);

        OauthTokenIssuer oauthTokenIssuer = new OauthTokenIssuer() {

            @Override
            public String accessToken(OAuthTokenReqMessageContext tokReqMsgCtx) throws OAuthSystemException {

                return null;
            }

            @Override
            public String refreshToken(OAuthTokenReqMessageContext tokReqMsgCtx) throws OAuthSystemException {

                return null;
            }

            @Override
            public String authorizationCode(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException {

                return null;
            }

            @Override
            public String accessToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException {

                return null;
            }

            @Override
            public String refreshToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException {

                return null;
            }
        };

        when(mockOAuthServerConfiguration.getIdentityOauthTokenIssuer()).thenReturn(oauthTokenIssuer);
    }

    @Test(dataProvider = "GetValidateGrantData")
    public void testValidateGrant(String clientId, String refreshToken, String accessToken, String tokenState,
                                  Boolean expected, Boolean isUsernameCaseSensitive) throws Exception {

        System.setProperty("carbon.home", "");
        whenNew(org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO.class).withNoArguments().thenReturn(mockTokenMgtDAO);
        RefreshTokenValidationDataDO validationDataDO =
                constructValidationDataDO(accessToken, tokenState, isUsernameCaseSensitive);
        when(mockTokenMgtDAO.validateRefreshToken(anyString(), anyString())).thenReturn(validationDataDO);

        if (isUsernameCaseSensitive) {
            when(IdentityUtil.isUserStoreInUsernameCaseSensitive(anyString())).thenReturn(true);
        } else {
            when(IdentityUtil.isUserStoreInUsernameCaseSensitive(anyString())).thenReturn(false);
        }

        if (StringUtils.equals(tokenState, OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED) && StringUtils.equals
                (clientId, "clientId2")) {

            AccessTokenDO[] accessTokenDOS = new AccessTokenDO[2];
            accessTokenDOS[0] = new AccessTokenDO();
            accessTokenDOS[0].setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
            accessTokenDOS[0].setRefreshToken(refreshToken);

            accessTokenDOS[1] = new AccessTokenDO();

            when(mockTokenMgtDAO.retrieveLatestAccessTokens(anyString(), any(AuthenticatedUser.class), anyString(),
                    anyString(), anyBoolean(), anyInt())).thenReturn(Arrays.asList(accessTokenDOS));
        }
        refreshGrantHandler = new RefreshGrantHandler();
        refreshGrantHandler.init();

        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        tokenReqDTO.setClientId(clientId);
        tokenReqDTO.setRefreshToken(refreshToken);
        OAuthTokenReqMessageContext tokenReqMessageContext = new OAuthTokenReqMessageContext(tokenReqDTO);

        Boolean actual = refreshGrantHandler.validateGrant(tokenReqMessageContext);
        assertEquals(expected, actual);
    }

    @DataProvider(name = "GetValidateGrantData")
    public Object[][] ValidateGrantData() {

        return new Object[][]{
                {"clientId1", refreshToken, accessToken, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE, true, false},
                {"clientId1", refreshToken, accessToken, OAuthConstants.TokenStates.TOKEN_STATE_INACTIVE, false, false},
                {"clientId1", refreshToken, accessToken, OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED, false, false},
                {"clientId1", refreshToken, accessToken, OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED, false, true},
                {"clientId2", refreshToken, accessToken, OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED, true, true},
                {"clientId2", "refreshToken2", accessToken, OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED, true, true},
                {"clientId1", refreshToken, null, null, false, false},
        };
    }

    private RefreshTokenValidationDataDO constructValidationDataDO(String accessToken, String refreshTokenState,
                                                                   Boolean isUsernameCaseSensitive) {

        RefreshTokenValidationDataDO validationDataDO = new RefreshTokenValidationDataDO();
        validationDataDO.setAccessToken(accessToken);
        validationDataDO.setRefreshTokenState(refreshTokenState);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        if (isUsernameCaseSensitive) {
            authenticatedUser.setUserName("UserName");
            authenticatedUser.setAuthenticatedSubjectIdentifier("PRIMARY/UserName");
        } else {
            authenticatedUser.setUserName("username");
            authenticatedUser.setAuthenticatedSubjectIdentifier("PRIMARY/username");
        }
        authenticatedUser.setFederatedUser(true);
        validationDataDO.setAuthorizedUser(authenticatedUser);
        return validationDataDO;
    }
}
