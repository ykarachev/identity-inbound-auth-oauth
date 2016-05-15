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

package org.wso2.carbon.identity.oauth2new.handler.grant;

import org.apache.commons.lang3.StringUtils;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2TokenMessageContext;
import org.wso2.carbon.identity.oauth2new.bean.message.request.token.password.PasswordGrantRequest;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2AuthnException;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2ClientException;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2RuntimeException;
import org.wso2.carbon.identity.oauth2new.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

public class PasswordGrantHandler extends AuthorizationGrantHandler {

    @Override
    public String getName() {
        return "PasswordGrantHandler";
    }

    @Override
    public boolean canHandle(MessageContext messageContext) {
        if(messageContext instanceof OAuth2TokenMessageContext) {
            if(GrantType.PASSWORD.toString().equals(((OAuth2TokenMessageContext) messageContext).getRequest()
                    .getGrantType())) {
                return true;
            }
        }
        return false;
    }

    public void validateGrant(OAuth2TokenMessageContext messageContext) throws OAuth2ClientException, OAuth2Exception {

        super.validateGrant(messageContext);

        String username = ((PasswordGrantRequest)messageContext.getRequest()).getUsername();
        String tenantAwareUserName = MultitenantUtils.getTenantAwareUsername(username);
        String userTenantDomain = MultitenantUtils.getTenantDomain(username);
        char[] password = ((PasswordGrantRequest)messageContext.getRequest()).getPassword();
        String clientId = messageContext.getClientId();
        String tenantDomain = messageContext.getRequest().getTenantDomain();
        ServiceProvider serviceProvider = null;

        // get ServiceProvider form application.mgt service

        if(!serviceProvider.isSaasApp() && !userTenantDomain.equals(tenantDomain)){
            String message = "Non-SaaS service provider tenant domain is not same as user tenant domain; " +
                    tenantDomain + " != " + userTenantDomain;
            throw OAuth2AuthnException.error(message);

        }

        RealmService realmService = OAuth2ServiceComponentHolder.getInstance().getRealmService();
        UserStoreManager userStoreManager = null;
        boolean authStatus;
        try {
            userStoreManager = realmService.getTenantUserRealm(IdentityTenantUtil.getTenantId(userTenantDomain))
                    .getUserStoreManager();
        } catch (UserStoreException e) {
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        }
        try {
            authStatus = userStoreManager.authenticate(tenantAwareUserName, new String(password));
        } catch (UserStoreException e) {
            throw OAuth2AuthnException.error(e.getMessage(), e);
        }
        if (authStatus) {
            if (username.indexOf(CarbonConstants.DOMAIN_SEPARATOR) < 0 &&
                    StringUtils.isNotBlank(UserCoreUtil.getDomainFromThreadLocal())) {
                username = UserCoreUtil.getDomainFromThreadLocal() + CarbonConstants.DOMAIN_SEPARATOR + username;
            }
            UserCoreUtil.addTenantDomainToEntry(tenantAwareUserName, userTenantDomain); // is this needed
            messageContext.setAuthzUser(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
        } else {
            throw OAuth2AuthnException.error("Authentication failed for " + username);
        }
    }
}
