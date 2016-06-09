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
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.oauth.dcr.DCRManagementService;
import org.wso2.carbon.identity.oauth.dcr.impl.DCRManagementServiceImpl;
import org.wso2.carbon.identity.oauth.dcr.processor.register.RegistrationRequestProcessor;
import org.wso2.carbon.identity.oauth.dcr.processor.register.factory.HttpRegistrationResponseFactory;
import org.wso2.carbon.identity.oauth.dcr.processor.register.factory.RegistrationRequestFactory;
import org.wso2.carbon.identity.oauth.dcr.processor.unregister.UnregistrationRequestProcessor;
import org.wso2.carbon.identity.oauth.dcr.processor.unregister.factory.HttpUnregistrationResponseFactory;
import org.wso2.carbon.identity.oauth.dcr.processor.unregister.factory.UnregistrationRequestFactory;

/**
 * @scr.component name="identity.oauth.dcr" immediate="true"
 * @scr.reference name="identity.application.management.service"
 * interface="org.wso2.carbon.identity.application.mgt.ApplicationManagementService"
 * cardinality="1..1" policy="dynamic"
 * bind="setApplicationManagementService" unbind="unsetApplicationManagementService"
 * @scr.reference name="identity.oauth.dcr.dcrservice"
 * interface="org.wso2.carbon.identity.oauth.dcr.DCRManagementService"
 * cardinality="0..1" policy="dynamic"
 * bind="setDynamicClientRegistrationService" unbind="unsetDynamicClientRegistrationService"
 */
public class DCRServiceComponent {

    private static final Log log = LogFactory.getLog(DCRServiceComponent.class);

    @SuppressWarnings("unused")
    protected void activate(ComponentContext componentContext) {
        try {
            componentContext.getBundleContext().registerService(DCRManagementService.class.getName(),new DCRManagementServiceImpl(), null);
            componentContext.getBundleContext().registerService(HttpIdentityRequestFactory.class.getName(),
                                                                new RegistrationRequestFactory(), null);
            componentContext.getBundleContext().registerService(IdentityProcessor.class.getName(),
                                                                new RegistrationRequestProcessor(), null);
            componentContext.getBundleContext().registerService(HttpIdentityResponseFactory.class.getName(),
                                                                new HttpRegistrationResponseFactory(), null);

            componentContext.getBundleContext().registerService(HttpIdentityRequestFactory.class.getName(),
                                                                new UnregistrationRequestFactory(), null);
            componentContext.getBundleContext().registerService(IdentityProcessor.class.getName(),
                                                                new UnregistrationRequestProcessor(), null);
            componentContext.getBundleContext().registerService(HttpIdentityResponseFactory.class.getName(),
                                                                new HttpUnregistrationResponseFactory(), null);


        }catch(Exception ee){
            ee.printStackTrace();
        }
    }

    @SuppressWarnings("unused")
    protected void deactivate(ComponentContext componentContext) {
        if (log.isDebugEnabled()) {
            log.debug("Stopping DCRServiceComponent");
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
        DCRDataHolder.getInstance().
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
        DCRDataHolder.getInstance().setApplicationManagementService(null);
    }

    /**
     * Sets DCRManagementService Service.
     *
     * @param DCRManagementService An instance of DCRManagementService
     */
    protected void setDynamicClientRegistrationService(DCRManagementService
                                                               DCRManagementService) {
        if (log.isDebugEnabled()) {
            log.debug("Setting DCRManagementService.");
        }
        DCRDataHolder.getInstance().setDCRManagementService(DCRManagementService);
    }

    /**
     * Unsets DCRManagementService.
     *
     * @param DCRManagementService An instance of DCRManagementService
     */
    protected void unsetDynamicClientRegistrationService(DCRManagementService DCRManagementService) {
        if (log.isDebugEnabled()) {
            log.debug("Unsetting DCRManagementService.");
        }
        DCRDataHolder.getInstance().setDCRManagementService(null);
    }

}
