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

import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.oauth2new.bean.message.request.OAuth2IdentityRequestFactory;
import org.wso2.carbon.identity.oauth2new.dao.OAuth2DAOHandler;
import org.wso2.carbon.identity.oauth2new.handler.client.ClientAuthHandler;
import org.wso2.carbon.identity.oauth2new.handler.grant.AuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2new.handler.issuer.AccessTokenResponseIssuer;
import org.wso2.carbon.identity.oauth2new.handler.persist.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2new.introspect.IntrospectionHandler;
import org.wso2.carbon.identity.oauth2new.processor.OAuth2IdentityRequestProcessor;
import org.wso2.carbon.registry.api.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.ArrayList;
import java.util.List;

public class OAuth2ServiceComponentHolder {

    private static OAuth2ServiceComponentHolder instance = new OAuth2ServiceComponentHolder();
    private RealmService realmService;
    private RegistryService registryService;
    private IdentityCoreInitializedEvent identityCoreInitializedEvent;
    private List<ClientAuthHandler> clientAuthHandlers = new ArrayList<>();
    private List<AccessTokenResponseIssuer> accessTokenIssuers = new ArrayList<>();
    private List<TokenPersistenceProcessor> tokenPersistenceProcessors = new ArrayList<>();
    private List<OAuth2DAOHandler> oAuth2DAOHandlers = new ArrayList<>();
    private List<AuthorizationGrantHandler> grantHandlers = new ArrayList<>();
    private List<IntrospectionHandler> introspectionHandlers = new ArrayList<>();

    private OAuth2ServiceComponentHolder() {

    }

    public static OAuth2ServiceComponentHolder getInstance() {
        return instance;
    }

    public void setRealmService(RealmService realmService) {
        this.realmService = realmService;
    }

    public RealmService getRealmService() {
        return realmService;
    }

    public void setRegistryService(RegistryService registryService) {
        this.registryService = registryService;
    }

    public RegistryService getRegistryService() {
        return registryService;
    }

    public void setIdentityCoreInitializedEvent(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        this.identityCoreInitializedEvent = identityCoreInitializedEvent;
    }

    public IdentityCoreInitializedEvent getIdentityCoreInitializedEvent() {
        return identityCoreInitializedEvent;
    }

    public List<ClientAuthHandler> getClientAuthHandlers() {
        return clientAuthHandlers;
    }

    public List<AccessTokenResponseIssuer> getAccessTokenIssuers() {
        return accessTokenIssuers;
    }

    public List<TokenPersistenceProcessor> getTokenPersistenceProcessors() {
        return tokenPersistenceProcessors;
    }

    public List<OAuth2DAOHandler> getOAuth2DAOHandlers() {
        return oAuth2DAOHandlers;
    }

    public List<AuthorizationGrantHandler> getGrantHandlers() {
        return grantHandlers;
    }

    public List<IntrospectionHandler> getIntrospectionHandlers() {
        return introspectionHandlers;
    }
}
