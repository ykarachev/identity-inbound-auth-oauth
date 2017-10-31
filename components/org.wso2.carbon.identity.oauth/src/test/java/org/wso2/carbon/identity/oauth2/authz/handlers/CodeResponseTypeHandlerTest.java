package org.wso2.carbon.identity.oauth2.authz.handlers;

import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.test.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.test.common.testng.WithH2Database;
import org.wso2.carbon.identity.test.common.testng.WithRealmService;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import java.util.Properties;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;

@WithCarbonHome
@WithH2Database(jndiName = "jdbc/WSO2IdentityDB", files = {"dbScripts/token.sql"})
@WithRealmService(tenantId = MultitenantConstants.SUPER_TENANT_ID)
@PrepareForTest({IdentityUtil.class, OAuthAppDAO.class})
public class CodeResponseTypeHandlerTest{
    OAuthAuthzReqMessageContext authAuthzReqMessageContext;
    OAuth2AuthorizeReqDTO authorizationReqDTO;

    @BeforeMethod
    public void setUp() throws Exception {
//        System.setProperty("carbon.home", System.getProperty("user.dir")
//                + File.separator + "target");
//        PowerMockito.mockStatic(IdentityUtil.class);
//        PowerMockito.when(IdentityUtil.getIdentityConfigDirPath())
//                .thenReturn(System.getProperty("user.dir") + File.separator + "src" + File.separator + "test"
//                        + File.separator + "resources" + File.separator + "conf");

        TokenResponseTypeHandler tokenResponseTypeHandler = new TokenResponseTypeHandler();
        authorizationReqDTO = new OAuth2AuthorizeReqDTO();

        authorizationReqDTO.setCallbackUrl("https://localhost:8000/callback");
        authorizationReqDTO.setConsumerKey("SDSDSDS23131231");
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("testUser");
        authenticatedUser.setTenantDomain("carbon.super");
        authenticatedUser.setUserStoreDomain("PTEST");
        authorizationReqDTO.setUser(authenticatedUser);
        authorizationReqDTO.setResponseType(OAuthConstants.GrantTypes.TOKEN);
        authAuthzReqMessageContext
                = new OAuthAuthzReqMessageContext(authorizationReqDTO);
        authAuthzReqMessageContext
                .setApprovedScope(new String[]{"scope1", "scope2", OAuthConstants.Scope.OPENID});
    }

    @AfterMethod
    public void tearDown() throws Exception {
    }

    @Test
    public void testIssue() throws Exception {

        //AppInfoCache appInfoCache = PowerMockito.mock(AppInfoCache.class);
        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setGrantTypes("implicit");
        oAuthAppDO.setOauthConsumerKey("SDSDSDS23131231");
        oAuthAppDO.setState("active");
        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserStoreDomain("PRIMARY");
        user.setUserName("testUser");

        oAuthAppDO.setUser(user);

        //   appInfoCache.addToCache("AppInfoCache", oAuthAppDO);
        //  appInfoCache.addToCache("SDSDSDS23131231", oAuthAppDO);
        //  PowerMockito.when(appInfoCache.isEnabled()).thenReturn(true);
        //Whitebox.setInternalState(AppInfoCache.class, "instance", appInfoCache);


        //PowerMockito.when(BaseCache.getValueFromCache(anyString())).thenReturn(oAuthAppDO);
        OAuthAppDAO oAuthAppDAO = PowerMockito.mock(OAuthAppDAO.class);
        PowerMockito.when(oAuthAppDAO.getAppInformation(anyString())).thenReturn(oAuthAppDO);
        OAuthAppDAO authAppDAO = new OAuthAppDAO();
        authAppDAO.addOAuthConsumer("testUser", MultitenantConstants.SUPER_TENANT_ID, "PRIMARY");
        authAppDAO.addOAuthApplication(oAuthAppDO);

        PowerMockito.when(IdentityUtil.isUserStoreInUsernameCaseSensitive(anyString(), anyInt())).thenReturn(false);

        CodeResponseTypeHandler codeResponseTypeHandler = new CodeResponseTypeHandler();
        codeResponseTypeHandler.issue(authAuthzReqMessageContext);
    }

    private OAuthAuthzReqMessageContext setSampleOAuthReqMessageContext(String grantType) {
        String effectiveGrantType = null;
        OAuth2AuthorizeReqDTO authorizationReqDTO = new OAuth2AuthorizeReqDTO();
        if (grantType == null) {
            effectiveGrantType = "noValue";
        } else {
            effectiveGrantType = grantType;
        }
        if (!(effectiveGrantType.equals("implicit") || effectiveGrantType.equals("dummy_code_2"))) {
            authorizationReqDTO.setResponseType(ResponseType.CODE.toString());
        } else {
            authorizationReqDTO.setResponseType(ResponseType.TOKEN.toString());
        }
        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setGrantTypes(grantType);
        authorizationReqDTO.addProperty("OAuthAppDO", "test");
        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName("testUser");
        authorizationReqDTO.setUser(user);
        authorizationReqDTO.setConsumerKey("AK56897987ASDAAD");
        authorizationReqDTO.setScopes(new String[]{"scope1", "scope2"});

        OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext =
                new OAuthAuthzReqMessageContext(authorizationReqDTO);
        oAuthAuthzReqMessageContext.addProperty("OAuthAppDO", oAuthAppDO);
        return oAuthAuthzReqMessageContext;
    }

    private static InitialContext createContext() throws NamingException {
        Properties env = new Properties();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.rmi.registry.RegistryContextFactory");
        env.put(Context.PROVIDER_URL, "rmi://localhost:1099");
        InitialContext context = new InitialContext(env);
        return context;
    }


}