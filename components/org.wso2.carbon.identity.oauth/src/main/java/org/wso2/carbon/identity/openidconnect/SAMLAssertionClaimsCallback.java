/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.openidconnect;

import com.nimbusds.jwt.JWTClaimsSet;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.xml.XMLObject;
import org.w3c.dom.Element;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.RoleMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.registry.api.RegistryException;
import org.wso2.carbon.registry.api.Resource;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.StringTokenizer;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.ACCESS_TOKEN;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.AUTHZ_CODE;

/**
 * Returns the claims of the SAML assertion
 */
public class SAMLAssertionClaimsCallback implements CustomClaimsCallbackHandler {

    private final static Log log = LogFactory.getLog(SAMLAssertionClaimsCallback.class);
    private final static String INBOUND_AUTH2_TYPE = "oauth2";
    private final static String OIDC_DIALECT = "http://wso2.org/oidc/claim";
    private static final String UPDATED_AT = "updated_at";
    private static final String PHONE_NUMBER_VERIFIED = "phone_number_verified";
    private static final String EMAIL_VERIFIED = "email_verified";
    private static final String ADDRESS_PREFIX = "address.";
    private static final String ADDRESS = "address";
    private static final String OIDC_SCOPE_CLAIM_SEPARATOR = ",";

    private static String userAttributeSeparator = FrameworkUtils.getMultiAttributeSeparator();

    @Override
    public void handleCustomClaims(JWTClaimsSet jwtClaimsSet, OAuthTokenReqMessageContext requestMsgCtx) {
        // reading the token set in the same grant
        Assertion assertion = (Assertion) requestMsgCtx.getProperty(OAuthConstants.OAUTH_SAML2_ASSERTION);
        if (assertion != null) {
            if (log.isDebugEnabled()) {
                log.debug("SAML Assertion found in OAuthTokenReqMessageContext to process claims.");
            }
            addSubjectClaimFromAssertion(jwtClaimsSet, assertion);
            addCustomClaimsFromAssertion(jwtClaimsSet, assertion);
        } else {
            // No SAML Assertion to work with so we retrieve the claims from cache/userStore/messageContext.
            if (log.isDebugEnabled()) {
                log.debug("Adding claims of user: " + requestMsgCtx.getAuthorizedUser() + " to the JWTClaimSet used " +
                        "to build the id_token.");
            }
            handleUserClaims(jwtClaimsSet, requestMsgCtx);
        }
    }

    private void handleUserClaims(JWTClaimsSet jwtClaimsSet, OAuthTokenReqMessageContext requestMsgCtx) {
        try {
            Map<String, Object> claims = getUserClaims(requestMsgCtx);
            setClaimsToJwtClaimSet(claims, jwtClaimsSet);
        } catch (OAuthSystemException e) {
            log.error("Error occurred while adding claims of user: " + requestMsgCtx.getAuthorizedUser() +
                    " to the JWTClaimSet used to build the id_token.", e);
        }
    }

    private void addCustomClaimsFromAssertion(JWTClaimsSet jwtClaimsSet, Assertion assertion) {
        List<AttributeStatement> attributeStatementList = assertion.getAttributeStatements();

        if (CollectionUtils.isNotEmpty(attributeStatementList)) {
            for (AttributeStatement statement : attributeStatementList) {
                List<Attribute> attributesList = statement.getAttributes();
                for (Attribute attribute : attributesList) {
                    setAttributeValuesAsClaim(jwtClaimsSet, attribute);
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("No <AttributeStatement> elements found in the SAML Assertion to process claims.");
            }
        }
    }

    private void addSubjectClaimFromAssertion(JWTClaimsSet jwtClaimsSet, Assertion assertion) {
        // Process <Subject> element in the SAML Assertion and populate subject claim in the JWTClaimSet.
        if (assertion.getSubject() != null) {
            String subject = assertion.getSubject().getNameID().getValue();
            if (log.isDebugEnabled()) {
                log.debug("Setting subject: " + subject + " found in <NameID> of the SAML Assertion.");
            }
            jwtClaimsSet.setSubject(subject);
        }
    }

    private void setAttributeValuesAsClaim(JWTClaimsSet jwtClaimsSet, Attribute attribute) {
        List<XMLObject> values = attribute.getAttributeValues();
        if (values != null) {
            List<String> attributeValues = getNonEmptyAttributeValues(attribute, values);
            if (log.isDebugEnabled()) {
                log.debug("Claim: " + attribute.getName() + " Value: " + attributeValues + " set in the JWTClaimSet.");
            }
            String joinedAttributeString = StringUtils.join(attributeValues, userAttributeSeparator);
            jwtClaimsSet.setClaim(attribute.getName(), joinedAttributeString);
        }
    }

    private List<String> getNonEmptyAttributeValues(Attribute attribute, List<XMLObject> values) {
        String attributeName = attribute.getName();
        List<String> attributeValues = new ArrayList<>();
        // Iterate the attribute values and combine them with the multi attribute separator to
        // form a single claim value.
        // Eg: value1 and value2 = value1,,,value2 (multi-attribute separator = ,,,)
        for (int i = 0; i < values.size(); i++) {
            Element value = attribute.getAttributeValues().get(i).getDOM();
            // Get the attribute value
            String attributeValue = value.getTextContent();
            if (StringUtils.isBlank(attributeValue)) {
                log.warn("Ignoring empty attribute value found for attribute: " + attributeName);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("AttributeValue: " + attributeValue + " found for Attribute: " + attributeName + ".");
                }
                attributeValues.add(attributeValue);
            }
        }
        return attributeValues;
    }

    @Override
    public void handleCustomClaims(JWTClaimsSet jwtClaimsSet, OAuthAuthzReqMessageContext authzReqMessageContext) {
        AuthenticatedUser authorizedUser = authzReqMessageContext.getAuthorizationReqDTO().getUser();
        if (log.isDebugEnabled()) {
            log.debug("Adding claims of user: " + authorizedUser + " to the JWTClaimSet used to build the id_token.");
        }

        try {
            Map<String, Object> claims = getUserClaims(authzReqMessageContext);
            setClaimsToJwtClaimSet(claims, jwtClaimsSet);
        } catch (OAuthSystemException e) {
            log.error("Error occurred while adding claims of user: " + authorizedUser + " to the JWTClaimSet used to " +
                    "build the id_token.", e);
        }
    }

    /**
     * Get response map
     *
     * @param requestMsgCtx Token request message context
     * @return Mapped claimed
     * @throws OAuthSystemException
     */
    private Map<String, Object> getUserClaims(OAuthTokenReqMessageContext requestMsgCtx) throws OAuthSystemException {

        Map<ClaimMapping, String> userAttributes;
        Map<String, Object> claims;

        // Get any user attributes that were cached against the access token
        userAttributes = getUserAttributesCachedAgainstToken(requestMsgCtx.getProperty(ACCESS_TOKEN));
        if (MapUtils.isEmpty(userAttributes)) {
            // TODO: add a log here
            userAttributes = getUserAttributesCachedAgainstAuthorizationCode(requestMsgCtx.getProperty(AUTHZ_CODE));
        }

        claims = getClaimMapForUser(requestMsgCtx, userAttributes);

        String tenantDomain = requestMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
        // Restrict Claims going into the token based on the scope
        return controlClaimsFromScope(requestMsgCtx.getScope(), tenantDomain, claims);
    }

    private Map<String, Object> getClaimMapForUser(OAuthTokenReqMessageContext requestMsgCtx,
                                                   Map<ClaimMapping, String> userAttributes) {
        Map<String, Object> claimMap = Collections.emptyMap();
        if (MapUtils.isEmpty(userAttributes)) {
            if (!requestMsgCtx.getAuthorizedUser().isFederatedUser()) {
                if (log.isDebugEnabled()) {
                    log.debug("User attributes not found in cache. Trying to retrieve attribute for local user: " +
                            requestMsgCtx.getAuthorizedUser());
                }
                try {
                    claimMap = getClaimsFromUserStore(requestMsgCtx);
                } catch (UserStoreException | IdentityApplicationManagementException | IdentityException e) {
                    log.error("Error occurred while getting claims for user " + requestMsgCtx.getAuthorizedUser(), e);
                }
            } else {
                claimMap = getClaimsMap(userAttributes);
            }
        } else {
            claimMap = getClaimsMap(userAttributes);
        }
        return claimMap;
    }

    private Map<ClaimMapping, String> getUserAttributesCachedAgainstAuthorizationCode(Object authorizationCode) {
        Map<ClaimMapping, String> userAttributes = Collections.emptyMap();
        if (authorizationCode != null) {
            // get the cached user claims against the authorization code if any
            userAttributes = getUserAttributesFromCacheUsingCode(authorizationCode.toString());
        }
        return userAttributes;
    }

    private Map<ClaimMapping, String> getUserAttributesCachedAgainstToken(Object accessToken) {
        Map<ClaimMapping, String> userAttributes = Collections.emptyMap();
        if (accessToken != null) {
            // get the user claims cached against the access token if any
            userAttributes = getUserAttributesFromCacheUsingToken(accessToken.toString());
        }
        return userAttributes;
    }

    private Map<String, Object> getUserClaims(OAuthAuthzReqMessageContext authzReqMessageContext)
            throws OAuthSystemException {

        Map<ClaimMapping, String> userAttributes;
        Map<String, Object> claims = Collections.emptyMap();

        userAttributes = getUserAttributesCachedAgainstToken(authzReqMessageContext.getProperty(ACCESS_TOKEN));

        if (MapUtils.isEmpty(userAttributes))
            if (!(authzReqMessageContext.getAuthorizationReqDTO().getUser().isFederatedUser())) {
                if (log.isDebugEnabled()) {
                    log.debug("User attributes not found in cache. Trying to retrieve attribute for user " +
                            authzReqMessageContext.getAuthorizationReqDTO().getUser());
                }
                try {
                    claims = getClaimsFromUserStore(authzReqMessageContext);
                } catch (UserStoreException | IdentityApplicationManagementException | IdentityException e) {
                    log.error("Error occurred while getting claims for user " +
                            authzReqMessageContext.getAuthorizationReqDTO().getUser(), e);
                }
            } else {
                claims = getClaimsMap(userAttributes);
            }
        else {
            claims = getClaimsMap(userAttributes);
        }
        String tenantDomain = authzReqMessageContext.getAuthorizationReqDTO().getTenantDomain();
        return controlClaimsFromScope(authzReqMessageContext.getApprovedScope(), tenantDomain, claims);
    }

    /**
     * Get claims map
     *
     * @param userAttributes User Attributes
     * @return User attribute map
     */
    private Map<String, Object> getClaimsMap(Map<ClaimMapping, String> userAttributes) {

        Map<String, Object> claims = new HashMap<>();
        if (MapUtils.isNotEmpty(userAttributes)) {
            for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                claims.put(entry.getKey().getRemoteClaim().getClaimUri(), entry.getValue());
            }
        }
        return claims;
    }

    /**
     * Get claims from user store
     *
     * @param requestMsgCtx Token request message context
     * @return Users claim map
     * @throws Exception
     */
    private Map<String, Object> getClaimsFromUserStore(OAuthTokenReqMessageContext requestMsgCtx)
            throws UserStoreException, IdentityApplicationManagementException, IdentityException {

        Map<String, Object> mappedAppClaims = new HashMap<>();
        String spTenantDomain = getServiceProviderTenantDomain(requestMsgCtx);
        ServiceProvider serviceProvider =
                getServiceProvider(requestMsgCtx.getOauth2AccessTokenReqDTO().getClientId(), spTenantDomain);

        if (serviceProvider == null) {
            return mappedAppClaims;
        }

        ClaimMapping[] requestedLocalClaimMap = serviceProvider.getClaimConfig().getClaimMappings();
        if (ArrayUtils.isEmpty(requestedLocalClaimMap)) {
            return mappedAppClaims;
        }

        AuthenticatedUser user = requestMsgCtx.getAuthorizedUser();
        String userTenantDomain = user.getTenantDomain();
        String username = user.toString();
        UserRealm realm = IdentityTenantUtil.getRealm(userTenantDomain, username);
        if (realm == null) {
            log.warn("Invalid tenant domain provided. Empty claim returned back for tenant " + userTenantDomain
                    + " and user " + username);
            return mappedAppClaims;
        }

        List<String> claimURIList = new ArrayList<>();
        for (ClaimMapping mapping : requestedLocalClaimMap) {
            if (mapping.isRequested()) {
                claimURIList.add(mapping.getLocalClaim().getClaimUri());
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Requested number of local claims: " + claimURIList.size());
        }

        String claimSeparator = FrameworkUtils.getMultiAttributeSeparator();
        Map<String, String> userClaims =
                getUserClaimsMap(serviceProvider, username, realm, claimURIList, claimSeparator);

        addUserClaimsInOidcDialect(mappedAppClaims, spTenantDomain, username, userClaims);

        if (StringUtils.isNotBlank(claimSeparator)) {
            mappedAppClaims.put(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR, claimSeparator);
        }

        return mappedAppClaims;
    }

    private void addUserClaimsInOidcDialect(Map<String, Object> mappedAppClaims,
                                            String spTenantDomain,
                                            String username,
                                            Map<String, String> userClaims) throws ClaimMetadataException {
        if (MapUtils.isEmpty(userClaims)) {
            // User claims can be empty if user does not exist in user stores. Probably a federated user.
            if (log.isDebugEnabled()) {
                log.debug("No claims found for " + username + " from user store.");
            }
        } else {
            // Retrieve OIDC to Local Claim Mappings.
            Map<String, String> oidcToLocalClaimMappings = ClaimMetadataHandler.getInstance()
                    .getMappingsMapFromOtherDialectToCarbon(OIDC_DIALECT, null, spTenantDomain, false);

            if (log.isDebugEnabled()) {
                log.debug("Number of user claims retrieved for " + username + " from user store: " + userClaims.size());
            }
            // get user claims in OIDC dialect
            mappedAppClaims.putAll(getUserClaimsInOidcDialect(oidcToLocalClaimMappings, userClaims));
        }
    }

    private Map<String, String> getUserClaimsMap(ServiceProvider serviceProvider,
                                                 String username,
                                                 UserRealm realm,
                                                 List<String> claimURIList,
                                                 String claimSeparator) throws FrameworkException, UserStoreException {
        Map<String, String> userClaims = null;
        try {
            userClaims = realm.getUserStoreManager().getUserClaimValues(
                    MultitenantUtils.getTenantAwareUsername(username),
                    claimURIList.toArray(new String[claimURIList.size()]), null);

            setSpMappedRoleClaim(serviceProvider, claimSeparator, userClaims);
        } catch (UserStoreException e) {
            if (e.getMessage().contains("UserNotFound")) {
                if (log.isDebugEnabled()) {
                    log.debug("User " + username + " not found in user store");
                }
            } else {
                throw e;
            }
        }
        return userClaims;
    }

    private void setSpMappedRoleClaim(ServiceProvider serviceProvider,
                                      String claimSeparator,
                                      Map<String, String> userClaims) throws FrameworkException {
        //set local2sp role mappings
        for (Map.Entry<String, String> claim : userClaims.entrySet()) {
            if (FrameworkConstants.LOCAL_ROLE_CLAIM_URI.equals(claim.getKey())) {
                String roleClaim = claim.getValue();
                List<String> rolesList = new LinkedList<>(Arrays.asList(roleClaim.split(claimSeparator)));

                String roles = getServiceProviderMappedUserRoles(serviceProvider, rolesList, claimSeparator);
                claim.setValue(roles);
                break;
            }
        }
    }

    private String getServiceProviderTenantDomain(OAuthTokenReqMessageContext requestMsgCtx) {
        String spTenantDomain = (String) requestMsgCtx.getProperty(MultitenantConstants.TENANT_DOMAIN);
        // There are certain flows where tenant domain is not added as a message context property.
        if (spTenantDomain == null) {
            spTenantDomain = requestMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
        }
        return spTenantDomain;
    }

    private ServiceProvider getServiceProvider(String clientId,
                                               String spTenantDomain) throws IdentityApplicationManagementException {
        ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();
        String spName =
                applicationMgtService.getServiceProviderNameByClientId(clientId, INBOUND_AUTH2_TYPE, spTenantDomain);
        return applicationMgtService.getApplicationExcludingFileBasedSPs(spName, spTenantDomain);
    }

    /**
     * @param serviceProvider
     * @param locallyMappedUserRoles
     * @return
     */
    private static String getServiceProviderMappedUserRoles(ServiceProvider serviceProvider,
                                                            List<String> locallyMappedUserRoles,
                                                            String claimSeparator) throws FrameworkException {

        if (CollectionUtils.isNotEmpty(locallyMappedUserRoles)) {
            // Get Local Role to Service Provider Role mappings
            RoleMapping[] localToSpRoleMapping = serviceProvider.getPermissionAndRoleConfig().getRoleMappings();

            if (ArrayUtils.isNotEmpty(localToSpRoleMapping)) {
                for (RoleMapping roleMapping : localToSpRoleMapping) {
                    // check whether a local role is mapped to service provider role
                    if (locallyMappedUserRoles.contains(roleMapping.getLocalRole().getLocalRoleName())) {
                        // remove the local role from the list of user roles
                        locallyMappedUserRoles.remove(roleMapping.getLocalRole().getLocalRoleName());
                        // add the service provider mapped role
                        locallyMappedUserRoles.add(roleMapping.getRemoteRole());
                    }
                }
            }
        }

        return StringUtils.join(locallyMappedUserRoles, claimSeparator);
    }

    private Map<String, Object> getClaimsFromUserStore(OAuthAuthzReqMessageContext requestMsgCtx)
            throws IdentityApplicationManagementException, IdentityException, UserStoreException {

        Map<String, Object> mappedAppClaims = new HashMap<>();

        String spTenantDomain = (String) requestMsgCtx.getProperty(MultitenantConstants.TENANT_DOMAIN);

        // There are certain flows where tenant domain is not added as a message context property.
        if (spTenantDomain == null) {
            spTenantDomain = requestMsgCtx.getAuthorizationReqDTO().getTenantDomain();
        }

        ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();
        String spName = applicationMgtService
                .getServiceProviderNameByClientId(requestMsgCtx.getAuthorizationReqDTO().getConsumerKey(),
                        INBOUND_AUTH2_TYPE, spTenantDomain);
        ServiceProvider serviceProvider = applicationMgtService.getApplicationExcludingFileBasedSPs(spName,
                spTenantDomain);
        if (serviceProvider == null) {
            return mappedAppClaims;
        }
        ClaimMapping[] requestedLocalClaimMap = serviceProvider.getClaimConfig().getClaimMappings();
        if (requestedLocalClaimMap == null || !(requestedLocalClaimMap.length > 0)) {
            return new HashMap<>();
        }

        AuthenticatedUser user = requestMsgCtx.getAuthorizationReqDTO().getUser();
        String userTenantDomain = user.getTenantDomain();
        String username = user.toString();
        UserRealm realm = IdentityTenantUtil.getRealm(userTenantDomain, username);
        if (realm == null) {
            log.warn("Invalid tenant domain provided. Empty claim returned back for tenant " + userTenantDomain
                    + " and user " + user);
            return new HashMap<>();
        }

        List<String> claimURIList = new ArrayList<>();
        for (ClaimMapping mapping : requestedLocalClaimMap) {
            if (mapping.isRequested()) {
                claimURIList.add(mapping.getLocalClaim().getClaimUri());
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Requested number of local claims: " + claimURIList.size());
        }

        Map<String, String> spToLocalClaimMappings = ClaimMetadataHandler.getInstance().
                getMappingsMapFromOtherDialectToCarbon(OIDC_DIALECT, null, spTenantDomain, false);

        Map<String, String> userClaims = null;
        try {
            userClaims = realm.getUserStoreManager().getUserClaimValues(UserCoreUtil.addDomainToName(
                    user.getUserName(), user.getUserStoreDomain()), claimURIList.toArray(
                    new String[claimURIList.size()]), null);
        } catch (UserStoreException e) {
            if (e.getMessage().contains("UserNotFound")) {
                if (log.isDebugEnabled()) {
                    log.debug("User " + user + " not found in user store");
                }
            } else {
                throw e;
            }
        }

        if (MapUtils.isEmpty(userClaims)) {
            // User claims can be empty if user does not exist in user stores. Probably a federated user.
            if (log.isDebugEnabled()) {
                log.debug("No claims found for " + username + " from user store.");
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Number of user claims retrieved from user store: " + userClaims.size());
            }

            // get user claims in OIDC dialect
            mappedAppClaims.putAll(getUserClaimsInOidcDialect(spToLocalClaimMappings, userClaims));
        }

        String domain = user.getUserStoreDomain();
        RealmConfiguration realmConfiguration = ((org.wso2.carbon.user.core.UserStoreManager) realm
                .getUserStoreManager()).getSecondaryUserStoreManager(domain).getRealmConfiguration();
        String claimSeparator = realmConfiguration.getUserStoreProperty(
                IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);
        if (StringUtils.isNotBlank(claimSeparator)) {
            mappedAppClaims.put(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR, claimSeparator);
        }

        return mappedAppClaims;
    }

    /**
     * Get user claims in OIDC claim dialect
     *
     * @param oidcToLocalClaimMappings OIDC dialect to Local dialect claim mappings
     * @param userClaims               User claims in local dialect
     * @return Map of user claim values in OIDC dialect.
     */
    private Map<String, Object> getUserClaimsInOidcDialect(Map<String, String> oidcToLocalClaimMappings,
                                                           Map<String, String> userClaims) {

        Map<String, Object> userClaimsInOidcDialect = new HashMap<>();
        if (MapUtils.isNotEmpty(userClaims)) {
            for (Map.Entry<String, String> claimMapping : oidcToLocalClaimMappings.entrySet()) {
                String value = userClaims.get(claimMapping.getValue());
                if (value != null) {
                    userClaimsInOidcDialect.put(claimMapping.getKey(), value);
                    if (log.isDebugEnabled() &&
                            IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
                        log.debug("Mapped claim: key - " + claimMapping.getKey() + " value - " + value);
                    }
                }
            }
        }

        return userClaimsInOidcDialect;
    }

    /**
     * Get user attribute cached against the access token
     *
     * @param accessToken Access token
     * @return User attributes cached against the access token
     */
    private Map<ClaimMapping, String> getUserAttributesFromCacheUsingToken(String accessToken) {
        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug("Retrieving user attributes cached against access token: " + accessToken);
            } else {
                log.debug("Retrieving user attributes cached against access token.");
            }
        }

        AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(accessToken);
        AuthorizationGrantCacheEntry cacheEntry = AuthorizationGrantCache.getInstance()
                .getValueFromCacheByToken(cacheKey);

        return cacheEntry == null ? new HashMap<ClaimMapping, String>() : cacheEntry.getUserAttributes();
    }

    /**
     * Get user attributes cached against the authorization code
     *
     * @param authorizationCode Authorization Code
     * @return User attributes cached against the authorization code
     */
    private Map<ClaimMapping, String> getUserAttributesFromCacheUsingCode(String authorizationCode) {
        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.AUTHORIZATION_CODE)) {
                log.debug("Retrieving user attributes cached against authorization code: " + authorizationCode);
            } else {
                log.debug("Retrieving user attributes cached against authorization code.");
            }
        }

        AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(authorizationCode);
        AuthorizationGrantCacheEntry cacheEntry = AuthorizationGrantCache.getInstance()
                .getValueFromCacheByCode(cacheKey);

        return cacheEntry == null ? new HashMap<ClaimMapping, String>() : cacheEntry.getUserAttributes();
    }

    /**
     * Set claims from a Users claims Map object to a JWTClaimsSet object
     *
     * @param claims       Users claims
     * @param jwtClaimsSet JWTClaimsSet object
     */
    private void setClaimsToJwtClaimSet(Map<String, Object> claims, JWTClaimsSet jwtClaimsSet) {
        JSONArray claimValues;
        Object claimSeparator = claims.get(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);
        if (claimSeparator != null) {
            String claimSeparatorString = (String) claimSeparator;
            if (StringUtils.isNotBlank(claimSeparatorString)) {
                userAttributeSeparator = (String) claimSeparator;
            }
            claims.remove(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);
        }

        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            String value = entry.getValue().toString();
            claimValues = new JSONArray();
            if (userAttributeSeparator != null && value.contains(userAttributeSeparator)) {
                StringTokenizer st = new StringTokenizer(value, userAttributeSeparator);
                while (st.hasMoreElements()) {
                    String attributeValue = st.nextElement().toString();
                    if (StringUtils.isNotBlank(attributeValue)) {
                        claimValues.add(attributeValue);
                    }
                }
                jwtClaimsSet.setClaim(entry.getKey(), claimValues);
            } else {
                jwtClaimsSet.setClaim(entry.getKey(), entry.getValue());
            }
        }
    }

    /**
     * Use to control claims based on the requested scopes and defined scopes in the registry
     *
     * @param requestedScopes String[] requestedScopes
     * @param tenantDomain    String tenantDomain
     * @param userClaims      Object> claims
     * @return
     */
    private Map<String, Object> controlClaimsFromScope(String[] requestedScopes,
                                                       String tenantDomain,
                                                       Map<String, Object> userClaims) {
        List<String> claimUrisInRequestedScope;
        Map<String, Object> returnedClaims = new HashMap<>();
        Map<String, Object> claimValuesForAddressScope = new HashMap<>();

        // Load Tenant Registry and retrieve the oidc scope resource.
        Resource oidcScopesResource = getOidcScopeResource(tenantDomain);
        List<String> claimUrisInAddressScope = getAddressScopeClaims(oidcScopesResource);

        if (oidcScopesResource != null && oidcScopesResource.getProperties() != null) {
            Properties supportedOidcScopes = oidcScopesResource.getProperties();
            // Iterate through scopes requested in the OAuth2/OIDC request to filter claims
            for (String requestedScope : requestedScopes) {
                // Check if requested scope is a supported OIDC scope value
                if (supportedOidcScopes.containsKey(requestedScope)) {
                    // Requested scope is an registered OIDC scope. Get the claims belonging to the scope.
                    claimUrisInRequestedScope = getClaimUrisInSupportedOidcScope(oidcScopesResource, requestedScope);
                    // Iterate the user claims and pick ones that are supported by the OIDC scope.
                    for (Map.Entry<String, Object> claimMapEntry : userClaims.entrySet()) {
                        String claimUri = claimMapEntry.getKey();
                        Object claimValue = claimMapEntry.getValue();

                        if (claimUrisInRequestedScope.contains(claimUri)) {
                            // User claim is supported by the requested oidc scope.
                            if (isAddressClaim(claimUri, claimUrisInAddressScope)) {
                                // Handle Address Claims
                                populateClaimsForAddressScope(claimUri, claimValue,
                                        claimUrisInAddressScope, claimValuesForAddressScope);
                            } else {
                                returnedClaims.put(claimMapEntry.getKey(), userClaims.get(claimMapEntry.getKey()));
                            }
                        }
                    }
                }
            }
        }

        // Some OIDC claims need special formatting etc. These are handled below
        handleAddressClaim(returnedClaims, claimValuesForAddressScope);
        handleUpdateAtClaim(returnedClaims);
        handlePhoneNumberVerifiedClaim(returnedClaims);
        handleEmailVerifiedClaim(returnedClaims);

        return returnedClaims;
    }

    private void populateClaimsForAddressScope(String claimUri,
                                               Object claimValue,
                                               List<String> addressScopeClaims,
                                               Map<String, Object> claimsforAddressScope) {
        if (claimUri.contains(ADDRESS_PREFIX)) {
            claimsforAddressScope.put(claimUri.substring(ADDRESS_PREFIX.length()), claimValue);
        } else if (addressScopeClaims.contains(claimUri)) {
            claimsforAddressScope.put(claimUri, claimValue);
        }
    }

    private void handleAddressClaim(Map<String, Object> returnedClaims, Map<String, Object> claimsforAddressScope) {
        if (MapUtils.isNotEmpty(claimsforAddressScope)) {
            final JSONObject jsonObject = new JSONObject();
            claimsforAddressScope.forEach(jsonObject::put);
            returnedClaims.put(ADDRESS, jsonObject);
        }
    }

    private List<String> getAddressScopeClaims(Resource oidcScopesResource) {
        String[] addressScopeClaims;
        if (StringUtils.isBlank(oidcScopesResource.getProperty(ADDRESS))) {
            addressScopeClaims = new String[0];
        } else {
            addressScopeClaims = oidcScopesResource.getProperty(ADDRESS).split(OIDC_SCOPE_CLAIM_SEPARATOR);
        }
        return Arrays.asList(addressScopeClaims);
    }

    private boolean isAddressClaim(String claimUri, List<String> addressScopeClaims) {
        return StringUtils.isNotBlank(claimUri) &&
                (claimUri.contains(ADDRESS_PREFIX) || addressScopeClaims.contains(claimUri));
    }

    private List<String> getClaimUrisInSupportedOidcScope(Resource oidcScopesResource, String requestedScope) {
        String[] requestedScopeClaimsArray;
        if (StringUtils.isBlank(oidcScopesResource.getProperty(requestedScope))) {
            requestedScopeClaimsArray = new String[0];
        } else {
            requestedScopeClaimsArray = oidcScopesResource.getProperty(requestedScope).split(OIDC_SCOPE_CLAIM_SEPARATOR);
        }
        return Arrays.asList(requestedScopeClaimsArray);
    }

    private void handleUpdateAtClaim(Map<String, Object> returnClaims) {
        if (returnClaims.containsKey(UPDATED_AT) && returnClaims.get(UPDATED_AT) != null) {
            if (returnClaims.get(UPDATED_AT) instanceof String) {
                returnClaims.put(UPDATED_AT, Integer.parseInt((String) (returnClaims.get(UPDATED_AT))));
            }
        }
    }

    private void handlePhoneNumberVerifiedClaim(Map<String, Object> returnClaims) {
        if (returnClaims.containsKey(PHONE_NUMBER_VERIFIED))
            if (returnClaims.get(PHONE_NUMBER_VERIFIED) != null) {
                if (returnClaims.get(PHONE_NUMBER_VERIFIED) instanceof String) {
                    returnClaims.put(PHONE_NUMBER_VERIFIED, (Boolean.valueOf((String)
                            (returnClaims.get(PHONE_NUMBER_VERIFIED)))));
                }
            }
    }

    private void handleEmailVerifiedClaim(Map<String, Object> returnClaims) {
        if (returnClaims.containsKey(EMAIL_VERIFIED) && returnClaims.get(EMAIL_VERIFIED) != null) {
            if (returnClaims.get(EMAIL_VERIFIED) instanceof String) {
                returnClaims.put(EMAIL_VERIFIED, (Boolean.valueOf((String) (returnClaims.get(EMAIL_VERIFIED)))));
            }
        }
    }

    private Resource getOidcScopeResource(String tenantDomain) {
        Resource oidcScopesResource = null;
        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            startTenantFlow(tenantDomain, tenantId);
            RegistryService registry = OAuth2ServiceComponentHolder.getRegistryService();
            oidcScopesResource = registry.getConfigSystemRegistry(tenantId).get(OAuthConstants.SCOPE_RESOURCE_PATH);
        } catch (RegistryException e) {
            log.error("Error while obtaining registry collection from :" + OAuthConstants.SCOPE_RESOURCE_PATH, e);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
        return oidcScopesResource;
    }

    private void startTenantFlow(String tenantDomain, int tenantId) {
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
        carbonContext.setTenantId(tenantId);
        carbonContext.setTenantDomain(tenantDomain);
    }
}
