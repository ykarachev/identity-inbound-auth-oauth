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

package org.wso2.carbon.identity.oauth.dcr.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.oauth.dcr.DCRService;
import org.wso2.carbon.identity.oauth.dcr.impl.DCRServiceImpl;
import org.wso2.carbon.identity.oauth.dcr.register.DCRegisterHttpResponseFactory;
import org.wso2.carbon.identity.oauth.dcr.register.DCRegisterRequest;
import org.wso2.carbon.identity.oauth.dcr.register.DCRegisterRequestFactory;
import org.wso2.carbon.identity.oauth.dcr.register.DCRegisterRequestProcessor;
import org.wso2.carbon.identity.oauth.dcr.register.DCRegisterResponse;
import org.wso2.carbon.identity.oauth.dcr.unregister.DCUnregisterHttpResponseFactory;
import org.wso2.carbon.identity.oauth.dcr.unregister.DCUnregisterRequestFactory;
import org.wso2.carbon.identity.oauth.dcr.unregister.DCUnregisterRequestProcessor;
import org.wso2.carbon.identity.oauth.dcr.unregister.DCUnregisterResponse;

/**
 * @scr.component name="identity.oauth.dcr" immediate="true"
 * @scr.reference name="identity.application.management.service"
 * interface="org.wso2.carbon.identity.application.mgt.ApplicationManagementService"
 * cardinality="1..1" policy="dynamic"
 * bind="setApplicationManagementService" unbind="unsetApplicationManagementService"
 * @scr.reference name="identity.oauth.dcr.dcrservice"
 * interface="org.wso2.carbon.identity.oauth.dcr.DCRService"
 * cardinality="0..1" policy="dynamic"
 * bind="setDynamicClientRegistrationService" unbind="unsetDynamicClientRegistrationService"
 */
public class DynamicClientRegistrationServiceComponent {

    private static final Log log = LogFactory.getLog(DynamicClientRegistrationServiceComponent.class);

    @SuppressWarnings("unused")
    protected void activate(ComponentContext componentContext) {
        try {
            componentContext.getBundleContext().registerService(DCRService.class.getName(),new DCRServiceImpl(), null);
            componentContext.getBundleContext().registerService(HttpIdentityRequestFactory.class.getName(),
                                                                new DCRegisterRequestFactory(), null);
            componentContext.getBundleContext().registerService(IdentityProcessor.class.getName(),
                                                                new DCRegisterRequestProcessor(), null);
            componentContext.getBundleContext().registerService(HttpIdentityResponseFactory.class.getName(),
                                                                new DCRegisterHttpResponseFactory(), null);

            componentContext.getBundleContext().registerService(HttpIdentityRequestFactory.class.getName(),
                                                                new DCUnregisterRequestFactory(), null);
            componentContext.getBundleContext().registerService(IdentityProcessor.class.getName(),
                                                                new DCUnregisterRequestProcessor(), null);
            componentContext.getBundleContext().registerService(HttpIdentityResponseFactory.class.getName(),
                                                                new DCUnregisterHttpResponseFactory(), null);


        }catch(Exception ee){
            ee.printStackTrace();
        }
    }

    @SuppressWarnings("unused")
    protected void deactivate(ComponentContext componentContext) {
        if (log.isDebugEnabled()) {
            log.debug("Stopping DynamicClientRegistrationServiceComponent");
        }
    }

    /**
     * Sets ApplicationManagement Service.
     *
     * @param applicationManagementService An instance of ApplicationManagementService
     */
    protected void setApplicationManagementService(ApplicationManagementService applicationManagementService) {
        if (log.isDebugEnabled()) {
            log.debug("Setting ApplicationManagement Service");
        }
        DynamicClientRegistrationDataHolder.getInstance().
                setApplicationManagementService(applicationManagementService);
    }

    /**
     * Unsets ApplicationManagement Service.
     *
     * @param applicationManagementService An instance of ApplicationManagementService
     */
    protected void unsetApplicationManagementService(ApplicationManagementService applicationManagementService) {
        if (log.isDebugEnabled()) {
            log.debug("Unsetting ApplicationManagement.");
        }
        DynamicClientRegistrationDataHolder.getInstance().setApplicationManagementService(null);
    }

    /**
     * Sets DCRService Service.
     *
     * @param dcrService An instance of DCRService
     */
    protected void setDynamicClientRegistrationService(DCRService dcrService) {
        if (log.isDebugEnabled()) {
            log.debug("Setting DCRService.");
        }
        DynamicClientRegistrationDataHolder.getInstance().setDcrService(dcrService);
    }

    /**
     * Unsets DCRService.
     *
     * @param dcrService An instance of DCRService
     */
    protected void unsetDynamicClientRegistrationService(DCRService dcrService) {
        if (log.isDebugEnabled()) {
            log.debug("Unsetting DCRService.");
        }
        DynamicClientRegistrationDataHolder.getInstance().setDcrService(null);
    }

}
