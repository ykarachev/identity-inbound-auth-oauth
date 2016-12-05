package org.wso2.carbon.identity.oidc.session.servlet;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.CommonAuthenticationHandler;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationRequestCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthRequestWrapper;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthResponseWrapper;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oidc.session.OIDCSessionConstants;
import org.wso2.carbon.identity.oidc.session.cache.OIDCSessionDataCache;
import org.wso2.carbon.identity.oidc.session.cache.OIDCSessionDataCacheEntry;
import org.wso2.carbon.identity.oidc.session.cache.OIDCSessionDataCacheKey;
import org.wso2.carbon.identity.oidc.session.internal.OIDCSessionManagementComponentServiceHolder;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.api.UserStoreException;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class OIDCLogoutServlet extends HttpServlet {

    private static final Log log = LogFactory.getLog(OIDCLogoutServlet.class);

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        /**
         * Recommended Parameter : id_token_hint
         * As per the specification https://openid.net/specs/openid-connect-session-1_0.html#RFC6454, it's recommended
         * to expect id_token_hint parameter to determine which RP initiated the logout request.
         * Otherwise, it could lead to DoS attacks. Thus, at least explicit user confirmation is needed to act upon
         * such logout requests.
         *
         * Optional Parameter : post_logout_redirect_uri
         * This denotes the RP URL to be redirected after logout has been performed. This value must be previously
         * registered at IdP via post_logout_redirect_uris registration parameter or by some other configuration. And
         * the received URL should be validated to be one of registered.
         */

        /**
         * todo: At the moment we do not persist id_token issued for clients, thus we could not retrieve the RP that
         * todo: a specific id_token has been issued.
         * todo: Since we use a browser cookie to track the session, for the moment, we
         * todo: will validate if the logout request is being initiated by an active session via the cookie
         * todo: This need to be fixed such that we do not rely on the cookie and the request is validated against
         * todo: the id_token_hint received
         *
         * todo: Should provide a way to register post_logout_redirect_uris at IdP and should validate the received
         * todo: parameter against the set of registered values. This depends on retrieving client for the received
         * todo: id_token_hint value
         */

        String redirectURL;
        Cookie opBrowserStateCookie = OIDCSessionManagementUtil.getOPBrowserStateCookie(request);

        if (opBrowserStateCookie == null) {
            String msg = OIDCSessionConstants.OPBS_COOKIE_ID + " cookie not received. Missing session state.";
            if (log.isDebugEnabled()) {
                log.debug(msg);
            }
            redirectURL = OIDCSessionManagementUtil.getErrorPageURL(OAuth2ErrorCodes.ACCESS_DENIED, msg);
            response.sendRedirect(redirectURL);
            return;
        }

        if (!OIDCSessionManagementUtil.getSessionManager().sessionExists(opBrowserStateCookie.getValue())) {
            String msg = "No valid session found for the received session state.";
            if (log.isDebugEnabled()) {
                log.debug(msg);
            }
            redirectURL = OIDCSessionManagementUtil.getErrorPageURL(OAuth2ErrorCodes.ACCESS_DENIED, msg);
            response.sendRedirect(redirectURL);
            return;
        }

        String consent = request.getParameter(OIDCSessionConstants.OIDC_LOGOUT_CONSENT_PARAM);
        if (StringUtils.isNotBlank(consent)) {
            // User consent received for logout
            if (consent.equals(OAuthConstants.Consent.APPROVE)) {
                // User approved logout. Logout from authentication framework
                sendToFrameworkForLogout(request, response);
                return;
            } else {
                // User denied logout.
                redirectURL = OIDCSessionManagementUtil
                        .getErrorPageURL(OAuth2ErrorCodes.ACCESS_DENIED, "End User denied the logout request");
            }
        } else {
            // OIDC Logout response
            String sessionDataKey = request.getParameter(OIDCSessionConstants.OIDC_SESSION_DATA_KEY_PARAM);
            if (sessionDataKey != null) {
                handleLogoutResponseFromFramework(request, response);
                return;
            }
            // Get user consent to logout
            boolean skipConsent = OIDCSessionManagementUtil.getOpenIDConnectSkipeUserConsent();
            if (skipConsent) {
                sendToFrameworkForLogout(request, response);
                return;
            } else {
                redirectURL = OIDCSessionManagementUtil.getOIDCLogoutConsentURL();
            }
        }

        response.sendRedirect(redirectURL);
    }

    /**
     * Validate Id token signature
     * @param idToken
     * @return is validation state
     */
    private boolean validateIdToken(String idToken) {

        String tenantDomain = getTenantDomainForSignatureValidation(idToken);
        if (StringUtils.isEmpty(tenantDomain)) {
            return false;
        }
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        RSAPublicKey publicKey;

        try {
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);

            if (!tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                String ksName = tenantDomain.trim().replace(".", "-");
                String jksName = ksName + ".jks";
                publicKey = (RSAPublicKey) keyStoreManager.getKeyStore(jksName).getCertificate(tenantDomain)
                        .getPublicKey();
            } else {
                publicKey = (RSAPublicKey) keyStoreManager.getDefaultPublicKey();
            }
            SignedJWT signedJWT = SignedJWT.parse(idToken);
            JWSVerifier verifier = new RSASSAVerifier(publicKey);

            return signedJWT.verify(verifier);
        } catch (JOSEException | ParseException e) {
            log.error("Error occurred while validating id token signature.");
            return false;
        } catch (Exception e) {
            log.error("Error occurred while validating id token signature.");
            return false;
        }
    }

    /**
     * Get tenant domain for signature validation.
     * There is a problem If Id token signed using SP's tenant and there is no direct way to get the tenant domain
     * using client id. So have iterate all the Tenants until get the right client id.
     * @param idToken
     * @return Tenant domain
     */
    private String getTenantDomainForSignatureValidation(String idToken) {
        boolean isJWTSignedWithSPKey = OAuthServerConfiguration.getInstance().isJWTSignedWithSPKey();
        String tenantDomain = null;

        try {
            if (isJWTSignedWithSPKey) {

                String clientId = extractClientFromIdToken(idToken);
                Tenant[] tenants = OIDCSessionManagementComponentServiceHolder.getRealmService()
                        .getTenantManager()
                        .getAllTenants();
                ServiceProvider serviceProvider;
                for (Tenant tenant : tenants) {
                    ApplicationManagementService appInfo = ApplicationManagementService.getInstance();
                    serviceProvider = appInfo
                            .getServiceProviderByClientId(clientId, "oauth2", tenant.getDomain());
                    if (serviceProvider != null) {
                        tenantDomain = tenant.getDomain();
                        break;
                    }
                }
                if (tenantDomain == null) {
                    throw new InvalidOAuthClientException("Invalid client id.");
                }
            } else {
                String clientId = extractClientFromIdToken(idToken);
                OAuthAppDAO appDAO = new OAuthAppDAO();
                OAuthAppDO oAuthAppDO = appDAO.getAppInformation(clientId);
                tenantDomain = oAuthAppDO.getUser().getTenantDomain();
            }
        } catch (ParseException | UserStoreException | IdentityApplicationManagementException e) {
            log.error("Error occurred while extracting client id from id token", e);
            return null;
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            log.error("Error occurred while getting oauth application information.", e);
            return null;
        }
        return tenantDomain;
    }

    /**
     * Send request to consent URI
     * @param request
     * @param response
     * @throws IOException
     */
    private void sendToConsentUri(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        String redirectURL;
        String postLogoutRedirectUri = request
                .getParameter(OIDCSessionConstants.OIDC_POST_LOGOUT_REDIRECT_URI_PARAM);
        String state = request
                .getParameter(OIDCSessionConstants.OIDC_STATE_PARAM);
        String idTokenHint = request.getParameter(OIDCSessionConstants.OIDC_ID_TOKEN_HINT_PARAM);

        if (idTokenHint != null) {

            try {
                if (!validateIdToken(idTokenHint)) {
                    String msg = "Signature validation failed for id token.";
                    redirectURL = OIDCSessionManagementUtil
                            .getErrorPageURL(OAuth2ErrorCodes.ACCESS_DENIED, msg);
                    response.sendRedirect(redirectURL);
                    return;
                }

                String clientId = extractClientFromIdToken(idTokenHint);
                OAuthAppDAO appDAO = new OAuthAppDAO();
                OAuthAppDO oAuthAppDO = appDAO.getAppInformation(clientId);

                if (!validatePostLogoutUri(postLogoutRedirectUri, oAuthAppDO.getCallbackUrl())) {
                    String msg = "Post logout URI not does not match with registered callback URI.";
                    redirectURL = OIDCSessionManagementUtil
                            .getErrorPageURL(OAuth2ErrorCodes.ACCESS_DENIED, msg);
                    response.sendRedirect(redirectURL);
                    return;
                }
                Map<String, String> paramMap = new HashMap<>();
                paramMap.put(OIDCSessionConstants.OIDC_CACHE_CLIENT_ID_PARAM, clientId);
                OIDCSessionDataCacheEntry cacheEntry = new OIDCSessionDataCacheEntry();
                cacheEntry.setIdToken(idTokenHint);
                cacheEntry.setPostLogoutRedirectUri(postLogoutRedirectUri);
                cacheEntry.setState(state);
                cacheEntry.setParamMap(new ConcurrentHashMap<>(paramMap));

                Cookie opBrowserStateCookie = OIDCSessionManagementUtil.getOPBrowserStateCookie(request);
                addSessionDataToCache(opBrowserStateCookie.getValue(), cacheEntry);
                redirectURL = OIDCSessionManagementUtil.getOIDCLogoutConsentURL();
            } catch (ParseException e) {
                String msg = "No valid session found for the received session state.";
                redirectURL = OIDCSessionManagementUtil.getErrorPageURL(OAuth2ErrorCodes.ACCESS_DENIED, msg);
            } catch (InvalidOAuthClientException | IdentityOAuth2Exception e) {
                String msg = "Error occurred while getting application information. Client id not found";
                redirectURL = OIDCSessionManagementUtil.getErrorPageURL(OAuth2ErrorCodes.ACCESS_DENIED, msg);
            }
        } else {
            redirectURL = OIDCSessionManagementUtil.getOIDCLogoutConsentURL();
        }
        response.sendRedirect(redirectURL);
    }

    /**
     * Append state query parameter
     * @param redirectURL
     * @param stateParam
     * @return
     */
    private String appendStateQueryParam(String redirectURL, String stateParam) {

        if (StringUtils.isNotEmpty(stateParam)) {
            redirectURL = redirectURL + "?" + OIDCSessionConstants.OIDC_STATE_PARAM + "=" + stateParam;
        }
        return redirectURL;
    }

    /**
     * Validate post logout URI with registered callback URI
     * @param postLogoutUri
     * @param registeredCallbackUri
     * @return
     */
    private boolean validatePostLogoutUri(String postLogoutUri, String registeredCallbackUri) {

        String regexp = null;
        if (registeredCallbackUri.startsWith(OAuthConstants.CALLBACK_URL_REGEXP_PREFIX)) {
            regexp = registeredCallbackUri.substring(OAuthConstants.CALLBACK_URL_REGEXP_PREFIX.length());
        }

        if (regexp != null && postLogoutUri.matches(regexp)) {
            return true;
        } else if (registeredCallbackUri.equals(postLogoutUri)) {
            return true;
        } else {    // Provided Post logout redirect URL does not match the registered callback url.
            log.warn("Provided Post logout redirect URL does not match with the provided one.");
            return true;
        }
    }

    /**
     * Extract Client Id from Id token
     * @param idToken
     * @return Client Id
     * @throws ParseException
     */
    private String extractClientFromIdToken(String idToken) throws ParseException {

        return SignedJWT.parse(idToken).getJWTClaimsSet().getAudience().get(0);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doGet(request, response);
    }

    private void sendToFrameworkForLogout(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // Generate a SessionDataKey. Authentication framework expects this parameter
        String sessionDataKey = UUID.randomUUID().toString();

        //Add all parameters to authentication context before sending to authentication framework
        AuthenticationRequest authenticationRequest = new AuthenticationRequest();
        Map<String, String[]> map = new HashMap<>();
        map.put(OIDCSessionConstants.OIDC_SESSION_DATA_KEY_PARAM, new String[] { sessionDataKey });
        authenticationRequest.setRequestQueryParams(request.getParameterMap());
        authenticationRequest.addRequestQueryParam(FrameworkConstants.RequestParams.LOGOUT, new String[] { "true" });
        authenticationRequest.setCommonAuthCallerPath(request.getRequestURI());
        authenticationRequest.setPost(true);

        Cookie opBrowserStateCookie = OIDCSessionManagementUtil.getOPBrowserStateCookie(request);
        OIDCSessionDataCacheEntry cacheEntry = getSessionDataFromCache(opBrowserStateCookie.getValue());
        authenticationRequest.setRelyingParty(cacheEntry.getParamMap().get(OIDCSessionConstants.OIDC_CLIENT_ID_PARAM));
        addSessionDataToCache(sessionDataKey, cacheEntry);

        //Add headers to AuthenticationRequestContext
        for (Enumeration e = request.getHeaderNames(); e.hasMoreElements(); ) {
            String headerName = e.nextElement().toString();
            authenticationRequest.addHeader(headerName, request.getHeader(headerName));
        }

        AuthenticationRequestCacheEntry authenticationRequestCacheEntry =
                new AuthenticationRequestCacheEntry(authenticationRequest);
        addAuthenticationRequestToRequest(request, authenticationRequestCacheEntry);
        sendRequestToFramework(request, response, sessionDataKey, FrameworkConstants.RequestType.CLAIM_TYPE_OIDC);
    }

    private void handleLogoutResponseFromFramework(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        String sessionDataKey = request.getParameter(FrameworkConstants.SESSION_DATA_KEY);
        OIDCSessionDataCacheEntry cacheEntry = getSessionDataFromCache(sessionDataKey);
        if (cacheEntry != null) {
            String redirectURL = cacheEntry.getPostLogoutRedirectUri();
            if (redirectURL == null) {
                redirectURL = OIDCSessionManagementUtil.getOIDCLogoutURL();
            }
            redirectURL = appendStateQueryParam(redirectURL, cacheEntry.getState());
            removeSessionDataFromCache(sessionDataKey);
            Cookie opBrowserStateCookie = OIDCSessionManagementUtil.removeOPBrowserStateCookie(request, response);
            OIDCSessionManagementUtil.getSessionManager().removeOIDCSessionState(opBrowserStateCookie.getValue());
            response.sendRedirect(redirectURL);
        } else {
            response.sendRedirect(
                    OIDCSessionManagementUtil.getErrorPageURL(OAuth2ErrorCodes.SERVER_ERROR, "User logout failed"));
        }
    }

    private void addAuthenticationRequestToRequest(HttpServletRequest request,
                                                   AuthenticationRequestCacheEntry authRequest) {
        request.setAttribute(FrameworkConstants.RequestAttribute.AUTH_REQUEST, authRequest);
    }

    private void sendRequestToFramework(HttpServletRequest request, HttpServletResponse response, String sessionDataKey,
                                        String type) throws ServletException, IOException {

        CommonAuthenticationHandler commonAuthenticationHandler = new CommonAuthenticationHandler();

        CommonAuthRequestWrapper requestWrapper = new CommonAuthRequestWrapper(request);
        requestWrapper.setParameter(FrameworkConstants.SESSION_DATA_KEY, sessionDataKey);
        requestWrapper.setParameter(FrameworkConstants.RequestParams.TYPE, type);

        CommonAuthResponseWrapper responseWrapper = new CommonAuthResponseWrapper(response);
        commonAuthenticationHandler.doGet(requestWrapper, responseWrapper);

        Object object = request.getAttribute(FrameworkConstants.RequestParams.FLOW_STATUS);
        if (object != null) {
            AuthenticatorFlowStatus status = (AuthenticatorFlowStatus) object;
            if (status == AuthenticatorFlowStatus.INCOMPLETE) {
                response.sendRedirect(responseWrapper.getRedirectURL());
            }
        }

        if (object != null) {
            AuthenticatorFlowStatus status = (AuthenticatorFlowStatus) object;
            if (status == AuthenticatorFlowStatus.INCOMPLETE) {
                response.sendRedirect(responseWrapper.getRedirectURL());
            } else {
                handleLogoutResponseFromFramework(requestWrapper, response);
            }
        } else {
            handleLogoutResponseFromFramework(requestWrapper, response);
        }
    }

    private void addSessionDataToCache(String sessionDataKey, OIDCSessionDataCacheEntry cacheEntry) {

        OIDCSessionDataCacheKey cacheKey = new OIDCSessionDataCacheKey(sessionDataKey);
        OIDCSessionDataCache.getInstance().addToCache(cacheKey, cacheEntry);
    }

    private OIDCSessionDataCacheEntry getSessionDataFromCache(String sessionDataKey) {

        OIDCSessionDataCacheKey cacheKey = new OIDCSessionDataCacheKey(sessionDataKey);
        return OIDCSessionDataCache.getInstance().getValueFromCache(cacheKey);
    }

    private void removeSessionDataFromCache(String sessionDataKey) {

        OIDCSessionDataCacheKey cacheKey = new OIDCSessionDataCacheKey(sessionDataKey);
        OIDCSessionDataCache.getInstance().clearCacheEntry(cacheKey);
    }
}
