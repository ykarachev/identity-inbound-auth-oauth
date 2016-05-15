/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2new.admin.listener;

import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.listener.AbstractApplicationMgtListener;

/*
 * Since client secret is stored in IDN_OAUTH_CONSUMER_APPS table and not in SP_INBOUND_AUTH table,
 * this listener adds the client secret to the ServiceProvider object in runtime to be shown in the
 * "Inbound Authentication Configuration" section of the Service Provider in the admin console.
 */
public class OAuth2ApplicationMgtListener extends AbstractApplicationMgtListener {

    public static final String OAUTH2 = "oauth2";
    public static final String OAUTH2_CONSUMER_SECRET = "oauthConsumerSecret";

    @Override
    public int getDefaultOrderId() {
        return 11;
    }

    public boolean doPreUpdateApplication(ServiceProvider serviceProvider, String tenantDomain, String userName)
            throws IdentityApplicationManagementException {
        return true;
    }

    public boolean doPostGetServiceProvider(ServiceProvider serviceProvider, String serviceProviderName, String tenantDomain)
            throws IdentityApplicationManagementException {
        return true;
    }

    public boolean doPostGetServiceProviderByClientId(ServiceProvider serviceProvider, String clientId, String clientType,
                                                      String tenantDomain) throws IdentityApplicationManagementException {
        return true;
    }

    public boolean doPostCreateApplication(ServiceProvider serviceProvider, String tenantDomain, String userName) throws IdentityApplicationManagementException {
        return true;
    }

    public boolean doPostUpdateApplication(ServiceProvider serviceProvider, String tenantDomain, String userName) throws IdentityApplicationManagementException {
        return true;
    }

    @Override
    public boolean doPostGetApplicationExcludingFileBasedSPs(ServiceProvider serviceProvider, String applicationName, String tenantDomain) throws IdentityApplicationManagementException {
        return true;
    }
}