/*
 *  Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2new.admin.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.mgt.listener.ApplicationMgtListener;
import org.wso2.carbon.identity.oauth2new.admin.listener.OAuth2ApplicationMgtListener;
import org.wso2.carbon.identity.oauth2new.admin.listener.OAuth2TenantMgtListener;
import org.wso2.carbon.identity.oauth2new.admin.listener.OAuth2UserOperationEventListener;
import org.wso2.carbon.identity.oauth2new.admin.listener.OAuth2UserStoreConfigListener;
import org.wso2.carbon.identity.user.store.configuration.listener.UserStoreConfigListener;
import org.wso2.carbon.stratos.common.listeners.TenantMgtListener;
import org.wso2.carbon.user.core.listener.UserOperationEventListener;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * @scr.component name="identity.oauth2.admin.component" immediate="true"
 * @scr.reference name="user.realmservice.default"
 * interface="org.wso2.carbon.user.core.service.RealmService" cardinality="1..1"
 * policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 */
public class OAuth2AdminServiceComponent {

    private static Log log = LogFactory.getLog(OAuth2AdminServiceComponent.class);
    BundleContext bundleContext = null;
    private ServiceRegistration userOperationEventListenerReg = null;
    private ServiceRegistration applicationMgtListenerReg = null;
    private ServiceRegistration tenantMgtListenerReg = null;
    private ServiceRegistration userStoreConfigListenerReg = null;

    protected void activate(ComponentContext context) {

        userOperationEventListenerReg = context.getBundleContext().registerService(
                UserOperationEventListener.class.getName(), new OAuth2UserOperationEventListener(), null);
        bundleContext.registerService(ApplicationMgtListener.class.getName(), new OAuth2ApplicationMgtListener(),
                null);
        bundleContext.registerService(TenantMgtListener.class.getName(), new OAuth2TenantMgtListener(), null);
        bundleContext.registerService(UserStoreConfigListener.class.getName(), new OAuth2UserStoreConfigListener(),
                null);

        if (log.isDebugEnabled()) {
            log.debug("OAuth2UserOperationEventListener is registered");
            log.debug("OAuth2ApplicationMgtListener is registered");
            log.debug("OAuth2TenantMgtListener is registered");
            log.debug("OAuth2UserStoreConfigListener is registered");
            log.debug("OAuth2 Admin bundle is activated");
        }
    }

    protected void deactivate(ComponentContext context) {
        if (userOperationEventListenerReg != null) {
            userOperationEventListenerReg.unregister();
        }
        if (log.isDebugEnabled()) {
            log.debug("OAuth2UserOperationEventListener is registered");
        }
        if (applicationMgtListenerReg != null) {
            applicationMgtListenerReg.unregister();
        }
        if (log.isDebugEnabled()) {
            log.debug("OAuth2ApplicationMgtListener is registered");
        }
        if (tenantMgtListenerReg != null) {
            tenantMgtListenerReg.unregister();
        }
        if (log.isDebugEnabled()) {
            log.debug("OAuth2TenantMgtListener is registered");
        }
        if (userStoreConfigListenerReg != null) {
            userStoreConfigListenerReg.unregister();
        }
        if (log.isDebugEnabled()) {
            log.debug("OAuth2UserStoreConfigListener is registered");
            log.debug("OAuth2 Admin bundle is deactivated");
        }
    }


    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Setting the RealmService");
        }
        OAuth2AdminServiceComponentHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Unsetting the RealmService");
        }
        OAuth2AdminServiceComponentHolder.getInstance().setRealmService(null);
    }
}
