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

package org.wso2.carbon.identity.oauth2new.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.oauth2new.bean.message.request.OAuth2IdentityRequestFactory;
import org.wso2.carbon.identity.oauth2new.dao.OAuth2DAOHandler;
import org.wso2.carbon.identity.oauth2new.handler.client.ClientAuthHandler;
import org.wso2.carbon.identity.oauth2new.handler.grant.AuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2new.handler.issuer.AccessTokenResponseIssuer;
import org.wso2.carbon.identity.oauth2new.handler.persist.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2new.introspect.IntrospectionHandler;
import org.wso2.carbon.identity.oauth2new.model.OAuth2ServerConfig;
import org.wso2.carbon.identity.oauth2new.processor.OAuth2IdentityRequestProcessor;
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
 * @scr.reference name="oauth2.handler.client.auth"
 * interface="org.wso2.carbon.identity.oauth2new.handler.client.ClientAuthHandler" cardinality="0..n"
 * policy="dynamic" bind="addClientAuthHandler" unbind="removeClientAuthHandler"
 * @scr.reference name="oauth2.handler.issuer.token"
 * interface="org.wso2.carbon.identity.oauth2new.handler.issuer.AccessTokenResponseIssuer" cardinality="0..n"
 * policy="dynamic" bind="addAccessTokenResponseIssuer" unbind="removeAccessTokenResponseIssuer"
 * @scr.reference name="oauth2.handler.persist.token"
 * interface="org.wso2.carbon.identity.oauth2new.handler.persist.TokenPersistenceProcessor" cardinality="0..n"
 * policy="dynamic" bind="addTokenPersistenceProcessor" unbind="removeTokenPersistenceProcessor"
 * @scr.reference name="oauth2.handler.dao"
 * interface="org.wso2.carbon.identity.oauth2new.dao.OAuth2DAO" cardinality="0..n"
 * policy="dynamic" bind="addOAuth2DAOHandler" unbind="removeOAuth2DAOHandler"
 * @scr.reference name="oauth2.handler.grant"
 * interface="org.wso2.carbon.identity.oauth2new.handler.grant.AuthorizationGrantHandler" cardinality="0..n"
 * policy="dynamic" bind="addAuthorizationGrantHandler" unbind="removeAuthorizationGrantHandler"
 * @scr.reference name="oauth2.handler.introspection"
 * interface="org.wso2.carbon.identity.oauth2new.introspection.IntrospectionHandler" cardinality="0..n"
 * policy="dynamic" bind="addIntrospectionHandler" unbind="removeIntrospectionHandler"
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

    protected void addClientAuthHandler(ClientAuthHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Adding ClientAuthHandler " + handler.getName());
        }
        OAuth2ServiceComponentHolder.getInstance().getClientAuthHandlers().add(handler);
    }

    protected void removeClientAuthHandler(ClientAuthHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Removing ClientAuthHandler " + handler.getName());
        }
        OAuth2ServiceComponentHolder.getInstance().getClientAuthHandlers().remove(handler);
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

    protected void addTokenPersistenceProcessor(TokenPersistenceProcessor persistenceProcessor) {
        if (log.isDebugEnabled()) {
            log.debug("Adding AccessTokenResponseIssuer " + persistenceProcessor.getName());
        }
        OAuth2ServiceComponentHolder.getInstance().getTokenPersistenceProcessors().add(persistenceProcessor);
    }

    protected void removeTokenPersistenceProcessor(TokenPersistenceProcessor persistenceProcessor) {
        if (log.isDebugEnabled()) {
            log.debug("Removing AccessTokenResponseIssuer " + persistenceProcessor.getName());
        }
        OAuth2ServiceComponentHolder.getInstance().getTokenPersistenceProcessors().remove(persistenceProcessor);
    }

    protected void addOAuth2DAOHandler(OAuth2DAOHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Adding AccessTokenResponseIssuer " + handler.getName());
        }
        OAuth2ServiceComponentHolder.getInstance().getOAuth2DAOHandlers().add(handler);
    }

    protected void removeOAuth2DAOHandler(OAuth2DAOHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Removing AccessTokenResponseIssuer " + handler.getName());
        }
        OAuth2ServiceComponentHolder.getInstance().getOAuth2DAOHandlers().remove(handler);
    }

    protected void addAuthorizationGrantHandler(AuthorizationGrantHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Adding AuthorizationGrantHandler " + handler.getName());
        }
        OAuth2ServiceComponentHolder.getInstance().getGrantHandlers().add(handler);
    }

    protected void removeAuthorizationGrantHandler(AuthorizationGrantHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Removing AuthorizationGrantHandler " + handler.getName());
        }
        OAuth2ServiceComponentHolder.getInstance().getGrantHandlers().remove(handler);
    }

    protected void addIntrospectionHandler(IntrospectionHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Adding IntrospectionHandler " + handler.getName());
        }
        OAuth2ServiceComponentHolder.getInstance().getIntrospectionHandlers().add(handler);
    }

    protected void removeIntrospectionHandler(IntrospectionHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Removing IntrospectionHandler " + handler.getName());
        }
        OAuth2ServiceComponentHolder.getInstance().getIntrospectionHandlers().remove(handler);
    }
}
