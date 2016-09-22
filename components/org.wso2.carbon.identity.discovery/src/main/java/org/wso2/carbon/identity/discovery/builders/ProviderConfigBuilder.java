/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.discovery.builders;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.ServerConfigurationException;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.ExternalClaim;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.discovery.OIDCDiscoveryEndPointException;
import org.wso2.carbon.identity.discovery.OIDProviderConfigResponse;
import org.wso2.carbon.identity.discovery.OIDProviderRequest;
import org.wso2.carbon.identity.discovery.internal.OIDCDiscoveryDataHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.List;

/**
 * ProviderConfigBuilder builds the OIDProviderConfigResponse
 * giving the correct OprnIDConnect settings.
 * This should handle all the services to get the required data.
 */
public class ProviderConfigBuilder {

    private static Log log = LogFactory.getLog(ProviderConfigBuilder.class);
    private static final String OIDC_CLAIM_DIALECT = "http://wso2.org/oidc/claim";

    public OIDProviderConfigResponse buildOIDProviderConfig(OIDProviderRequest request) throws
            OIDCDiscoveryEndPointException, ServerConfigurationException {
        OIDProviderConfigResponse providerConfig = new OIDProviderConfigResponse();
        providerConfig.setIssuer(IdentityUtil.getServerURL("", false, false));
        providerConfig.setAuthorizationEndpoint(OAuth2Util.OAuthURL.getOAuth2AuthzEPUrl());
        providerConfig.setTokenEndpoint(OAuth2Util.OAuthURL.getOAuth2TokenEPUrl());
        providerConfig.setUserinfoEndpoint(OAuth2Util.OAuthURL.getOAuth2UserInfoEPUrl());
        List<String> scopes = OAuth2Util.getOIDCScopes(request.getTenantDomain());
        providerConfig.setScopesSupported(scopes.toArray(new String[scopes.size()]));
        try {
            List<ExternalClaim> claims = OIDCDiscoveryDataHolder.getInstance().getClaimManagementService()
                    .getExternalClaims(OIDC_CLAIM_DIALECT, request.getTenantDomain());
            String[] claimArray = new String[claims.size()];
            for (int i = 0; i < claims.size(); i++) {
                claimArray[i] = claims.get(i).getClaimURI();
            }
            providerConfig.setClaimsSupported(claimArray);
        } catch (ClaimMetadataException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while retrieving OIDC claim dialect");
            }
        }
        temp_Value_Settings(providerConfig, request);
        return providerConfig;
    }

    /**
     * This is an temporary method.
     * Provide additional services to get following parameters.
     */
    private void temp_Value_Settings(OIDProviderConfigResponse providerConfig, OIDProviderRequest request) {
        String serverurl = IdentityUtil.getServerURL("", false, false);

        //TODO add a method to retrieve the dcr endpoint
        providerConfig.setRegistrationEndpoint(serverurl + "/identity/connect/register");

        //TODO add a method to retrieve jwks endpoint
        providerConfig.setJwksUri(serverurl + "/oauth2/jwks/" + request.getTenantDomain());

        providerConfig.setIdTokenSigningAlgValuesSupported(new String[]{"RS256", "RS384", "RS512", "HS256", "HS384",
                "HS512", "ES256", "ES384", "ES512"});

        providerConfig.setResponseTypesSupported(new String[]{"code", "id_token", "token id_token", "token"});

        providerConfig.setSubjectTypesSupported(new String[]{"pairwise"});

    }
}
