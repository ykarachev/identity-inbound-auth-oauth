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

package org.wso2.carbon.identity.oauth2poc.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.oauth2poc.handler.issuer.AccessTokenResponseIssuer;
import org.wso2.carbon.identity.oauth2poc.model.OAuth2ServerConfig;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * @scr.component name="identity.oauth2.component" immediate="true"
 * @scr.reference name="registry.service"
 * interface="org.wso2.carbon.registry.core.service.RegistryService"
 * cardinality="1..1" policy="dynamic" bind="setRegistryService"
 * unbind="unsetRegistryService"
 * @scr.reference name="user.realmservice.default"
 * interface="org.wso2.carbon.user.core.service.RealmService" cardinality="1..1"
 * policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 * @scr.reference name="identityCoreInitializedEventService"
 * interface="org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent" cardinality="1..1"
 * policy="dynamic" bind="setIdentityCoreInitializedEventService" unbind="unsetIdentityCoreInitializedEventService"
 * @scr.reference name="oauth2.handler.issuer.token"
 * interface="org.wso2.carbon.identity.oauth2new.handler.issuer.AccessTokenResponseIssuer" cardinality="0..n"
 * policy="dynamic" bind="addAccessTokenResponseIssuer" unbind="removeAccessTokenResponseIssuer"
 *
 */
public class OAuth2ServiceComponent {

    private static Log log = LogFactory.getLog(OAuth2ServiceComponent.class);

    protected void activate(ComponentContext context) {

        try {
            OAuth2ServerConfig.getInstance();
            if (log.isDebugEnabled()) {
                log.debug("OAuth2 bundle is activated");
            }
        } catch (Throwable e) {
            log.fatal("Error occurred while activating OAuth2 bundle");
        }
    }

    protected void deactivate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.debug("OAuth2 bundle is deactivated");
        }
    }

    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Setting the RealmService");
        }
        OAuth2ServiceComponentHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Unsetting the RealmService");
        }
        OAuth2ServiceComponentHolder.getInstance().setRealmService(null);
    }

    protected void setRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("Setting the RegistryService");
        }
        OAuth2ServiceComponentHolder.getInstance().setRegistryService(registryService);
    }

    protected void unsetRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("Unsetting the RegistryService");
        }
        OAuth2ServiceComponentHolder.getInstance().setRegistryService(null);
    }

    protected void setIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        if (log.isDebugEnabled()) {
            log.debug("Setting the IdentityCoreInitializedEventService");
        }
        OAuth2ServiceComponentHolder.getInstance().setIdentityCoreInitializedEvent(identityCoreInitializedEvent);
    }

    protected void unsetIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        if (log.isDebugEnabled()) {
            log.debug("Unsetting the IdentityCoreInitializedEventService");
        }
        OAuth2ServiceComponentHolder.getInstance().setIdentityCoreInitializedEvent(null);
    }

    protected void addAccessTokenResponseIssuer(AccessTokenResponseIssuer handler) {
        if (log.isDebugEnabled()) {
            log.debug("Adding AccessTokenResponseIssuer " + handler.getName());
        }
        OAuth2ServiceComponentHolder.getInstance().getAccessTokenIssuers().add(handler);
    }

    protected void removeAccessTokenResponseIssuer(AccessTokenResponseIssuer handler) {
        if (log.isDebugEnabled()) {
            log.debug("Removing AccessTokenResponseIssuer " + handler.getName());
        }
        OAuth2ServiceComponentHolder.getInstance().getAccessTokenIssuers().remove(handler);
    }
}
