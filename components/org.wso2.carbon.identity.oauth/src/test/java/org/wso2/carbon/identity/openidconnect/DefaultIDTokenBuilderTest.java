package org.wso2.carbon.identity.openidconnect;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.logging.Log;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.IObjectFactory;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.security.MessageDigest;
import java.util.LinkedHashSet;

import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.mockito.Matchers.any;
import static org.testng.Assert.*;

@PrepareForTest({IdentityProviderManager.class, FederatedAuthenticatorConfig.class, IdentityApplicationManagementUtil.class, OAuthServerConfiguration.class, OAuth2Util.class, JWTClaimsSet.class, FederatedAuthenticatorConfig.class, MessageDigest.class, IdentityConfigParser.class, OAuth2ServiceComponentHolder.class})
public class DefaultIDTokenBuilderTest {
    @Mock
    Log log;

    @Mock
    IdentityProvider identityProvider;

    @Mock
    CustomClaimsCallbackHandler customClaimsCallbackHandler;

    @Mock
    OAuthServerConfiguration oAuthServerConfiguration;

    @Mock
    JWTClaimsSet jwtClaimsSet;

    @Mock
    OAuthAuthzReqMessageContext request;

    @Mock
    OAuth2AuthorizeReqDTO oAuth2AuthorizeReqDTO;

    @Mock
    OAuth2AuthorizeRespDTO oAuth2AuthorizeRespDTO;

    @Mock
    IdentityProviderManager identityProviderManager;

    @Mock
    FederatedAuthenticatorConfig federatedAuthenticatorConfig;

    @Mock
    AuthenticatedUser authenticatedUser;

    @Mock
    Property property;

    @Mock
    MessageDigest messageDigest;

    @Mock
    OAuthTokenReqMessageContext request1;

    @Mock
    OAuth2AccessTokenReqDTO tokenReqDTO;

    @Mock
    OAuth2AccessTokenRespDTO oAuth2AccessTokenRespDTO;

    @Mock
    JWT jwt;

    @Mock
    IdentityConfigParser identityConfigParser;

    @Mock
    ApplicationManagementService applicationManagementService;

    @Mock
    ServiceProvider serviceProvider;

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    @Test
    public void testBuildIDToken() throws Exception {
        request1 = mock(OAuthTokenReqMessageContext.class);
        tokenReqDTO = mock(OAuth2AccessTokenReqDTO.class);
        when(request1.getOauth2AccessTokenReqDTO()).thenReturn(tokenReqDTO);
        when(tokenReqDTO.getTenantDomain()).thenReturn("tenant1");
        identityProvider = mock(IdentityProvider.class);
        mockStatic(IdentityProviderManager.class);
        when(IdentityProviderManager.getInstance()).thenReturn(identityProviderManager);
        when(identityProviderManager.getResidentIdP(anyString())).thenReturn(identityProvider);

        FederatedAuthenticatorConfig[] federatedAuthenticatorConfigs = new FederatedAuthenticatorConfig[10];
        when(identityProvider.getFederatedAuthenticatorConfigs()).thenReturn(federatedAuthenticatorConfigs);

        mockStatic(IdentityApplicationManagementUtil.class);
        when(IdentityApplicationManagementUtil.getFederatedAuthenticator(federatedAuthenticatorConfigs, "tenant2")).thenReturn(federatedAuthenticatorConfig);
        Property[] properties = new Property[1];
        Property property = new Property();
        property.setName("IdPEntityId");
        property.setValue("localhost");
        properties[0] = property;

        federatedAuthenticatorConfig.setProperties(properties);
        FederatedAuthenticatorConfig[] federatedAuthenticatorConfig1 = new FederatedAuthenticatorConfig[10];
        when(identityProvider.getFederatedAuthenticatorConfigs()).thenReturn(federatedAuthenticatorConfig1);

        mockStatic(IdentityApplicationManagementUtil.class);
        when(IdentityApplicationManagementUtil.getFederatedAuthenticator(federatedAuthenticatorConfigs, IdentityApplicationConstants.Authenticator.OIDC.NAME)).thenReturn(federatedAuthenticatorConfig);
        when(IdentityApplicationManagementUtil.getProperty(any(Property[].class), anyString())).thenCallRealMethod();

        when(federatedAuthenticatorConfig.getProperties()).thenReturn(properties);

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(oAuthServerConfiguration.getTimeStampSkewInSeconds()).thenReturn((long) 3);
        mockStatic(OAuth2Util.class);
        when(oAuthServerConfiguration.getOpenIDConnectIDTokenExpiration()).thenReturn(String.valueOf((int) 78383));
        when(OAuth2Util.mapDigestAlgorithm(any(JWSAlgorithm.class))).thenReturn(String.valueOf(JWSAlgorithm.RS256));

        when(request1.getAuthorizedUser()).thenReturn(authenticatedUser);
        when(authenticatedUser.getAuthenticatedSubjectIdentifier()).thenReturn("Subject_Identifier");

        applicationManagementService = mock(ApplicationManagementService.class);
        serviceProvider = mock(ServiceProvider.class);

        mockStatic(OAuth2ServiceComponentHolder.class);
        when(OAuth2ServiceComponentHolder.getApplicationMgtService()).thenReturn(applicationManagementService);
        when(applicationManagementService.getServiceProviderByClientId(anyString(), anyString(), anyString())).thenReturn(serviceProvider);
        when(tokenReqDTO.getClientId()).thenReturn("Client name");

        JWSAlgorithm jwsAlgorithm1 = new JWSAlgorithm("Algo3");
        when(OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(anyString())).thenReturn(jwsAlgorithm1);
        when(OAuth2Util.mapDigestAlgorithm(any(JWSAlgorithm.class))).thenReturn("SHA-256");
        DefaultIDTokenBuilder defaultIDTokenBuilder = new DefaultIDTokenBuilder();

        mockStatic(MessageDigest.class);
        when(MessageDigest.getInstance(String.valueOf(JWSAlgorithm.RS256))).thenReturn(messageDigest);
        when(oAuth2AccessTokenRespDTO.getAccessToken()).thenReturn("AccessToken");

        mockStatic(IdentityConfigParser.class);
        when(IdentityConfigParser.getInstance()).thenReturn(identityConfigParser);
        when(oAuthServerConfiguration.getOpenIDConnectCustomClaimsCallbackHandler()).thenReturn(customClaimsCallbackHandler);
        doNothing().when(customClaimsCallbackHandler).handleCustomClaims(jwtClaimsSet, request);

        when(OAuth2Util.signJWT(any(JWTClaimsSet.class), any(JWSAlgorithm.class), anyString())).thenReturn(jwt);
        DefaultIDTokenBuilder defaultIDTokenBuilder1 = new DefaultIDTokenBuilder();
        assertNotEquals(defaultIDTokenBuilder1.buildIDToken(request1, oAuth2AccessTokenRespDTO), "TestPasssed");
    }

    @Test
    public void testBuildIDToken1() throws Exception {
        request = mock(OAuthAuthzReqMessageContext.class);
        identityProvider = mock(IdentityProvider.class);
        identityProviderManager = mock(IdentityProviderManager.class);
        authenticatedUser = mock(AuthenticatedUser.class);
        when(request.getAuthorizationReqDTO()).thenReturn(oAuth2AuthorizeReqDTO);
        when(oAuth2AuthorizeReqDTO.getTenantDomain()).thenReturn("carbon.super");
        mockStatic(IdentityProviderManager.class);
        when(IdentityProviderManager.getInstance()).thenReturn(identityProviderManager);
        when(identityProviderManager.getResidentIdP(anyString())).thenReturn(identityProvider);

        Property[] properties = new Property[1];
        Property property = new Property();
        property.setName("IdPEntityId");
        property.setValue("localhost");
        properties[0] = property;

        federatedAuthenticatorConfig.setProperties(properties);
        FederatedAuthenticatorConfig[] federatedAuthenticatorConfigs = new FederatedAuthenticatorConfig[10];
        when(identityProvider.getFederatedAuthenticatorConfigs()).thenReturn(federatedAuthenticatorConfigs);

        mockStatic(IdentityApplicationManagementUtil.class);
        when(IdentityApplicationManagementUtil.getFederatedAuthenticator(federatedAuthenticatorConfigs, IdentityApplicationConstants.Authenticator.OIDC.NAME)).thenReturn(federatedAuthenticatorConfig);
        when(IdentityApplicationManagementUtil.getProperty(any(Property[].class), anyString())).thenCallRealMethod();
        when(federatedAuthenticatorConfig.getProperties()).thenReturn(properties);

        when(oAuth2AuthorizeReqDTO.getUser()).thenReturn(authenticatedUser);
        when(authenticatedUser.getAuthenticatedSubjectIdentifier()).thenReturn("User1");
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(oAuthServerConfiguration.getTimeStampSkewInSeconds()).thenReturn((long) 3);
        mockStatic(OAuth2Util.class);
        when(oAuthServerConfiguration.getOpenIDConnectIDTokenExpiration()).thenReturn(String.valueOf((int) 78383));

        when(oAuth2AuthorizeReqDTO.getNonce()).thenReturn("Nonce1");
        LinkedHashSet set1 = new LinkedHashSet(10);
        when(oAuth2AuthorizeReqDTO.getACRValues()).thenReturn(set1);
        when(oAuth2AuthorizeReqDTO.getResponseType()).thenReturn("Response1");

        JWSAlgorithm jwsAlgorithm = new JWSAlgorithm("Algorithm8");
        when(OAuth2Util.mapDigestAlgorithm(any(JWSAlgorithm.class))).thenReturn("SHA-256");
        when(oAuthServerConfiguration.getIdTokenSignatureAlgorithm()).thenReturn("Algo2");
        mockStatic(FederatedAuthenticatorConfig.class);

        JWSAlgorithm jwsAlgorithm1 = new JWSAlgorithm("Algo3");
        when(OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(anyString())).thenReturn(jwsAlgorithm1);
        DefaultIDTokenBuilder defaultIDTokenBuilder = new DefaultIDTokenBuilder();

        mockStatic(MessageDigest.class);
        when(MessageDigest.getInstance(String.valueOf(JWSAlgorithm.RS256))).thenReturn(messageDigest);
        when(oAuth2AuthorizeRespDTO.getAccessToken()).thenReturn("AccessToken");
        when(oAuth2AuthorizeReqDTO.getConsumerKey()).thenReturn("key1");
        mockStatic(IdentityConfigParser.class);
        when(IdentityConfigParser.getInstance()).thenReturn(identityConfigParser);
        when(oAuthServerConfiguration.getOpenIDConnectCustomClaimsCallbackHandler()).thenReturn(customClaimsCallbackHandler);
        doNothing().when(customClaimsCallbackHandler).handleCustomClaims(jwtClaimsSet, request);

        when(OAuth2Util.signJWT(any(JWTClaimsSet.class), any(JWSAlgorithm.class), anyString())).thenReturn(jwt);
        assertNotEquals(defaultIDTokenBuilder.buildIDToken(request, oAuth2AuthorizeRespDTO), "Test passed1");
    }
}
