/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.openidconnect;

import net.minidev.json.JSONObject;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.registry.api.RegistryException;
import org.wso2.carbon.registry.api.Resource;
import org.wso2.carbon.registry.core.service.RegistryService;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static org.apache.commons.collections.MapUtils.isEmpty;

/**
 * Utility to handle OIDC Claim related functions.
 */
public class OIDCClaimUtil {

    private static final String UPDATED_AT = "updated_at";
    private static final String PHONE_NUMBER_VERIFIED = "phone_number_verified";
    private static final String EMAIL_VERIFIED = "email_verified";
    private static final String ADDRESS_PREFIX = "address.";
    private static final String ADDRESS = "address";
    public static final String ADDRESS_SCOPE = "address";
    private static final String OIDC_SCOPE_CLAIM_SEPARATOR = ",";

    private static final Log log = LogFactory.getLog(OIDCClaimUtil.class);

    private OIDCClaimUtil() {
    }

    /**
     * Filter user claims based on OIDC Scopes defined.
     * <p>
     * Each OIDC Scope defined has a set of permitted claims. First we consider the requested scopes and aggregate
     * the allowed claims for each requested scope if they are defined OIDC Scopes. Then we filter the user claims
     * which belong to the aggregated allowed claims.
     * </p>
     *
     * @param spTenantDomain  Tenant domain of the service provider to which the OAuth app belongs to.
     * @param requestedScopes Request scopes in the OIDC request.
     * @param userClaims      Retrieved claim values of the authenticated user.
     * @return Claim Map after filtering user claims based on defined scopes.
     */
    public static Map<String, Object> getClaimsFilteredByOIDCScopes(String spTenantDomain,
                                                                    String[] requestedScopes,
                                                                    Map<String, Object> userClaims) {

        if (isEmpty(userClaims)) {
            // No user claims to filter.
            return new HashMap<>();
        }

        List<String> claimUrisInRequestedScope;
        Map<String, Object> returnedClaims = new HashMap<>();
        Map<String, Object> claimValuesForAddressScope = new HashMap<>();

        // <"openid", "first_name,last_name,username">
        Properties properties = getOIDCScopes(spTenantDomain);
        if (isNotEmpty(properties)) {
            List<String> claimUrisInAddressScope = getAddressScopeClaims(properties);
            // Iterate through scopes requested in the OAuth2/OIDC request to filter claims
            for (String requestedScope : requestedScopes) {
                // Check if requested scope is a supported OIDC scope value
                if (properties.containsKey(requestedScope)) {
                    // Requested scope is an registered OIDC scope. Get the claims belonging to the scope.
                    claimUrisInRequestedScope = getClaimUrisInSupportedOidcScope(properties, requestedScope);
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

        // Some OIDC claims need special formatting etc. These are handled below.
        handleAddressClaim(returnedClaims, claimValuesForAddressScope);
        handleUpdateAtClaim(returnedClaims);
        handlePhoneNumberVerifiedClaim(returnedClaims);
        handleEmailVerifiedClaim(returnedClaims);

        return returnedClaims;
    }

    protected static boolean isNotEmpty(Properties properties) {
        return properties != null && !properties.isEmpty();
    }


    private static void populateClaimsForAddressScope(String claimUri,
                                                      Object claimValue,
                                                      List<String> addressScopeClaims,
                                                      Map<String, Object> claimsforAddressScope) {
        if (claimUri.contains(ADDRESS_PREFIX)) {
            claimsforAddressScope.put(claimUri.substring(ADDRESS_PREFIX.length()), claimValue);
        } else if (addressScopeClaims.contains(claimUri)) {
            claimsforAddressScope.put(claimUri, claimValue);
        }
    }

    private static void handleAddressClaim(Map<String, Object> returnedClaims,
                                           Map<String, Object> claimsforAddressScope) {
        if (MapUtils.isNotEmpty(claimsforAddressScope)) {
            final JSONObject jsonObject = new JSONObject();
            claimsforAddressScope.forEach(jsonObject::put);
            returnedClaims.put(ADDRESS, jsonObject);
        }
    }

    private static List<String> getAddressScopeClaims(Properties oidcProperties) {
        return getClaimUrisInSupportedOidcScope(oidcProperties, ADDRESS_SCOPE);
    }

    private static boolean isAddressClaim(String claimUri, List<String> addressScopeClaims) {
        return StringUtils.isNotBlank(claimUri) &&
                (claimUri.contains(ADDRESS_PREFIX) || addressScopeClaims.contains(claimUri));
    }

    private static List<String> getClaimUrisInSupportedOidcScope(Properties properties, String requestedScope) {
        String[] requestedScopeClaimsArray;
        if (StringUtils.isBlank(properties.getProperty(requestedScope))) {
            requestedScopeClaimsArray = new String[0];
        } else {
            requestedScopeClaimsArray = properties.getProperty(requestedScope).split(OIDC_SCOPE_CLAIM_SEPARATOR);
        }
        return Arrays.asList(requestedScopeClaimsArray);
    }

    private static void handleUpdateAtClaim(Map<String, Object> returnClaims) {
        if (returnClaims.containsKey(UPDATED_AT) && returnClaims.get(UPDATED_AT) != null) {
            if (returnClaims.get(UPDATED_AT) instanceof String) {
                returnClaims.put(UPDATED_AT, Long.parseLong((String) (returnClaims.get(UPDATED_AT))));
            }
        }
    }

    private static void handlePhoneNumberVerifiedClaim(Map<String, Object> returnClaims) {
        if (returnClaims.containsKey(PHONE_NUMBER_VERIFIED))
            if (returnClaims.get(PHONE_NUMBER_VERIFIED) != null) {
                if (returnClaims.get(PHONE_NUMBER_VERIFIED) instanceof String) {
                    returnClaims.put(PHONE_NUMBER_VERIFIED, (Boolean.valueOf((String)
                            (returnClaims.get(PHONE_NUMBER_VERIFIED)))));
                }
            }
    }

    private static void handleEmailVerifiedClaim(Map<String, Object> returnClaims) {
        if (returnClaims.containsKey(EMAIL_VERIFIED) && returnClaims.get(EMAIL_VERIFIED) != null) {
            if (returnClaims.get(EMAIL_VERIFIED) instanceof String) {
                returnClaims.put(EMAIL_VERIFIED, (Boolean.valueOf((String) (returnClaims.get(EMAIL_VERIFIED)))));
            }
        }
    }

    private static Properties getOIDCScopes(String tenantDomain) {
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

        Properties propertiesToReturn = new Properties();
        if (oidcScopesResource != null) {
            for (Object scopeProperty : oidcScopesResource.getProperties().keySet()) {
                String propertyKey = (String) scopeProperty;
                propertiesToReturn.setProperty(propertyKey, oidcScopesResource.getProperty(propertyKey));
            }
        }
        return propertiesToReturn;
    }

    private static void startTenantFlow(String tenantDomain, int tenantId) {
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
        carbonContext.setTenantId(tenantId);
        carbonContext.setTenantDomain(tenantDomain);
    }
}
