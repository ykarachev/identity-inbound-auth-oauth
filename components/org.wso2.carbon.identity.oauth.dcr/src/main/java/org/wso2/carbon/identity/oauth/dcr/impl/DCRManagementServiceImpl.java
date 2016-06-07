/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * you may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.dcr.impl;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.context.RegistryType;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.OAuthAdminService;
import org.wso2.carbon.identity.oauth.dcr.DCRManagementException;
import org.wso2.carbon.identity.oauth.dcr.DCRManagementService;
import org.wso2.carbon.identity.oauth.dcr.internal.DynamicClientRegistrationDataHolder;
import org.wso2.carbon.identity.oauth.dcr.processor.register.model.OAuthApplication;
import org.wso2.carbon.identity.oauth.dcr.processor.register.model.RegistrationProfile;
import org.wso2.carbon.identity.oauth.dcr.util.DCRConstants;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class DCRManagementServiceImpl implements DCRManagementService {

    private static final Log log = LogFactory.getLog(DCRManagementServiceImpl.class);

    private static final String TOKEN_SCOPE = "tokenScope";
    private static final String AUTH_TYPE_OAUTH_2 = "oauth2";
    private static final String OAUTH_CONSUMER_SECRET = "oauthConsumerSecret";
    private static final String OAUTH_VERSION = "OAuth-2.0";

    /**
     * This method will register a new OAuth application using the data provided by
     * RegistrationProfile.
     *
     * @param profile - RegistrationProfile of the OAuth application to be created.
     * @return OAuthApplication object which holds the necessary data of created OAuth app.
     * @throws DCRManagementException
     */
    @Override
    public OAuthApplication registerOAuthApplication(RegistrationProfile profile)
            throws DCRManagementException {
        OAuthApplication oAuthApplication = new OAuthApplication();
        String applicationName = profile.getClientName();

        if (log.isDebugEnabled()) {
            log.debug("Trying to register OAuth application: '" + applicationName + "'");
        }

        String tokenScopes[] = { profile.getTokenScope() };
        oAuthApplication.addParameter(TOKEN_SCOPE, Arrays.toString(tokenScopes));
        OAuthApplication info;
        try {
            info = this.createOAuthApplication(profile);
        } catch (IdentityException e) {
            throw new DCRManagementException("Can not create OAuth application  : " + applicationName, e);
        }

        if (info == null || info.getJsonString() == null) {
            throw new DCRManagementException(
                    "OAuth app does not contain required data: '" + applicationName + "'");
        }

        oAuthApplication.setClientName(info.getClientName());
        oAuthApplication.setClientId(info.getClientId());
        oAuthApplication.getRedirectUrls().add(info.getRedirectUrls().get(0));
        oAuthApplication.setClientSecret(info.getClientSecret());

        try {
            JSONObject jsonObject = new JSONObject(info.getJsonString());
            if (jsonObject.has(DCRConstants.ClientMetadata.OAUTH_REDIRECT_URIS)) {
                oAuthApplication.addParameter(DCRConstants.ClientMetadata.OAUTH_REDIRECT_URIS,
                        jsonObject.get(DCRConstants.ClientMetadata.OAUTH_REDIRECT_URIS));
            }

            if (jsonObject.has(DCRConstants.ClientMetadata.OAUTH_CLIENT_GRANT)) {
                oAuthApplication.addParameter(DCRConstants.ClientMetadata.OAUTH_CLIENT_GRANT,
                        jsonObject.get(DCRConstants.ClientMetadata.OAUTH_CLIENT_GRANT));
            }
        } catch (JSONException e) {
            throw new DCRManagementException(
                    "Can not retrieve information of the created OAuth application", e);
        }
        return oAuthApplication;
    }

    /**
     * @param profile - RegistrationProfile of the OAuth application to be created.
     * @return OAuthApplication object which holds the necessary data of created OAuth app.
     * @throws DCRManagementException
     * @throws IdentityException
     */
    private OAuthApplication createOAuthApplication(RegistrationProfile profile)
            throws DCRManagementException, IdentityException {

        //Subscriber's name should be passed as a parameter, since it's under the subscriber
        //the OAuth App is created.
        String userId = profile.getOwner();
        String applicationName = profile.getClientName();
        String grantType = profile.getGrantType();

        if (StringUtils.isEmpty(userId)) {
            return null;
        }

        String tenantDomain = MultitenantUtils.getTenantDomain(userId);
        String baseUser = CarbonContext.getThreadLocalCarbonContext().getUsername();
        String userName = MultitenantUtils.getTenantAwareUsername(userId);

        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain, true);

        // Acting as the provided user. When creating Service Provider/OAuth App,
        // username is fetched from CarbonContext
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(userName);

        try {
            // Append the username before Application name to make application name unique across two users.
            applicationName = replaceInvalidChars(userName) + "_" + applicationName;

            // Create the Service Provider
            ServiceProvider serviceProvider = new ServiceProvider();
            serviceProvider.setApplicationName(applicationName);
            User user = new User();
            user.setUserName(userName);
            user.setTenantDomain(tenantDomain);
            serviceProvider.setOwner(user);

            serviceProvider.setDescription("Service Provider for application " + applicationName);
            ApplicationManagementService appMgtService = DynamicClientRegistrationDataHolder.getInstance().
                    getApplicationManagementService();
            if (appMgtService == null) {
                throw new IllegalStateException("Error occurred while retrieving Application Management Service");
            }

            ServiceProvider existingServiceProvider = appMgtService.getServiceProvider(applicationName, tenantDomain);
            if (existingServiceProvider == null) {
                appMgtService.createApplication(serviceProvider, tenantDomain, userName);
            }

            ServiceProvider createdServiceProvider = appMgtService.getServiceProvider(applicationName, tenantDomain);
            if (createdServiceProvider == null) {
                throw new DCRManagementException(
                        "Couldn't create Service Provider Application " + applicationName);
            }
            //Set SaaS app option
            createdServiceProvider.setSaasApp(false);
            // Then Create OAuthApp
            OAuthAdminService oAuthAdminService = new OAuthAdminService();

            OAuthConsumerAppDTO oAuthConsumerApp = new OAuthConsumerAppDTO();
            oAuthConsumerApp.setApplicationName(applicationName);
            //TODO: After implement multi-urls to the oAuth application, we have to change this API call
            if(profile.getRedirectUris().size()==0){
                throw new DCRManagementException(
                        "redirect_uris can't be empty.");
            }
            oAuthConsumerApp.setCallbackUrl(profile.getRedirectUris().get(0));
            oAuthConsumerApp.setGrantTypes(grantType);
            oAuthConsumerApp.setOAuthVersion(OAUTH_VERSION);
            if (log.isDebugEnabled()) {
                log.debug("Creating OAuth App " + applicationName);
            }

            if ((existingServiceProvider == null) || (existingServiceProvider.getInboundAuthenticationConfig().
                    getInboundAuthenticationRequestConfigs().length == 0)) {
                oAuthAdminService.registerOAuthApplicationData(oAuthConsumerApp);
            }

            if (log.isDebugEnabled()) {
                log.debug("Created OAuth App " + applicationName);
            }

            OAuthConsumerAppDTO createdApp = oAuthAdminService
                    .getOAuthApplicationDataByAppName(oAuthConsumerApp.getApplicationName());
            if (log.isDebugEnabled()) {
                log.debug("Retrieved Details for OAuth App " + createdApp.getApplicationName());
            }
            // Set the OAuthApp in InboundAuthenticationConfig
            InboundAuthenticationConfig inboundAuthenticationConfig = new InboundAuthenticationConfig();
            List<InboundAuthenticationRequestConfig> inboundAuthenticationRequestConfigs = new ArrayList<>();

            InboundAuthenticationRequestConfig inboundAuthenticationRequestConfig = new InboundAuthenticationRequestConfig();
            inboundAuthenticationRequestConfig.setInboundAuthKey(createdApp.getOauthConsumerKey());
            inboundAuthenticationRequestConfig.setInboundAuthType(AUTH_TYPE_OAUTH_2);
            String oauthConsumerSecret = createdApp.getOauthConsumerSecret();
            if (oauthConsumerSecret != null && !oauthConsumerSecret.isEmpty()) {
                Property property = new Property();
                property.setName(OAUTH_CONSUMER_SECRET);
                property.setValue(oauthConsumerSecret);
                Property[] properties = { property };
                inboundAuthenticationRequestConfig.setProperties(properties);
            }
            inboundAuthenticationRequestConfigs.add(inboundAuthenticationRequestConfig);
            inboundAuthenticationConfig.setInboundAuthenticationRequestConfigs(inboundAuthenticationRequestConfigs
                    .toArray(new InboundAuthenticationRequestConfig[inboundAuthenticationRequestConfigs.size()]));
            createdServiceProvider.setInboundAuthenticationConfig(inboundAuthenticationConfig);

            // Update the Service Provider app to add OAuthApp as an Inbound Authentication Config
            appMgtService.updateApplication(createdServiceProvider, tenantDomain, userName);

            OAuthApplication oAuthApplication = new OAuthApplication();
            oAuthApplication.setClientId(createdApp.getOauthConsumerKey());
            oAuthApplication.getRedirectUrls().add(createdApp.getCallbackUrl());
            oAuthApplication.setClientSecret(oauthConsumerSecret);
            oAuthApplication.setClientName(createdApp.getApplicationName());

            oAuthApplication
                    .addParameter(DCRConstants.ClientMetadata.OAUTH_REDIRECT_URIS, createdApp.getCallbackUrl());
            oAuthApplication
                    .addParameter(DCRConstants.ClientMetadata.OAUTH_CLIENT_GRANT, createdApp.getGrantTypes());

            return oAuthApplication;
        } catch (IdentityApplicationManagementException e) {
            throw new DCRManagementException(
                    "Error occurred while creating ServiceProvider for app " + applicationName, e);
        } catch (Exception e) {
            throw new DCRManagementException("Error occurred while creating OAuthApp " + applicationName,
                    e);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(baseUser);
        }
    }

    /**
     * This method will unregister a created OAuth application.
     *
     * @param userId          - UserId of the owner
     * @param applicationName - OAuth application name
     * @param consumerKey     - ConsumerKey of the OAuth application
     * @return The status of the operation
     * @throws DCRManagementException
     */
    @Override
    public void unregisterOAuthApplication(String userId, String applicationName, String consumerKey)
            throws DCRManagementException {

        if (!StringUtils.isNotEmpty(userId) || !StringUtils.isNotEmpty(applicationName) || !StringUtils
                .isNotEmpty(consumerKey)) {
            throw new DCRManagementException(
                    "Username, Application Name and Consumer Key cannot be null or empty");
        }
        String tenantDomain = MultitenantUtils.getTenantDomain(userId);
        String userName = MultitenantUtils.getTenantAwareUsername(userId);

        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain, true);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(userName);

        OAuthAdminService oAuthAdminService = new OAuthAdminService();
        OAuthConsumerAppDTO oAuthConsumerApp = null ;
        try {
            oAuthConsumerApp = oAuthAdminService.getOAuthApplicationData(consumerKey);
        } catch (Exception e) {
            //We had to catch Exception here because getOAuthApplicationData can throw exceptions of java.lang.Exception
            // class.

        }

        if (oAuthConsumerApp != null) {
            try {
                oAuthAdminService.removeOAuthApplicationData(consumerKey);
                ApplicationManagementService appMgtService = DynamicClientRegistrationDataHolder.getInstance().
                        getApplicationManagementService();

                if (appMgtService == null) {
                    throw new IllegalStateException("Error occurred while retrieving Application Management Service");
                }
                ServiceProvider createdServiceProvider = appMgtService.getServiceProvider(applicationName, tenantDomain);
                if (createdServiceProvider == null) {
                    throw new DCRManagementException(
                            "Couldn't retrieve Service Provider Application " + applicationName);
                }
                appMgtService.deleteApplication(applicationName, tenantDomain, userName);

            } catch (IdentityApplicationManagementException e) {
                throw new DCRManagementException(
                        "Error occurred while removing ServiceProvider for application '" + applicationName + "'", e);
            } catch (IdentityOAuthAdminException e) {
                throw new DCRManagementException("Error occurred while removing application '" +
                                       applicationName + "'", e);
            } finally {
                PrivilegedCarbonContext.endTenantFlow();
            }
        }
    }

    /**
     * This method will check the existence of an OAuth application provided application-name.
     *
     * @param applicationName - OAuth application name
     * @return The status of the operation
     * @throws DCRManagementException
     */
    @Override
    public boolean isOAuthApplicationAvailable(String applicationName) throws DCRManagementException {
        ApplicationManagementService appMgtService = DynamicClientRegistrationDataHolder.getInstance().
                getApplicationManagementService();
        if (appMgtService == null) {
            throw new IllegalStateException("Error occurred while retrieving Application Management Service");
        }
        try {
            return appMgtService
                    .getServiceProvider(applicationName, CarbonContext.getThreadLocalCarbonContext().getTenantDomain())
                    != null;
        } catch (IdentityApplicationManagementException e) {
            throw new DCRManagementException(
                    "Error occurred while retrieving information of OAuthApp " + applicationName, e);
        }
    }

    private String replaceInvalidChars(String username) {
        return username.replaceAll("@", "_AT_");
    }

    protected Registry getConfigSystemRegistry() {
        return (Registry) PrivilegedCarbonContext.getThreadLocalCarbonContext().getRegistry(RegistryType.
                SYSTEM_CONFIGURATION);
    }

}
