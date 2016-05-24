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

package org.wso2.carbon.identity.oauth2poc.handler.request;

import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.application.authentication.framework.FrameworkHandlerResponse;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.processor.handler.request.RequestHandlerException;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.application.mgt.internal.ApplicationManagementServiceComponentHolder;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.oauth2poc.OAuth2;
import org.wso2.carbon.identity.oauth2poc.bean.message.request.authz.OAuth2AuthzRequest;

/*
 * InboundRequestProcessor for OAuth2 Authorization Endpoint
 */
public class AuthzRequestHandler extends OAuth2RequestHandler {

    @Override
    public String getName() {
        return "AuthzRequestHandler";
    }

    public boolean canHandle(MessageContext messageContext) {
        AuthenticationContext authenticationContext = (AuthenticationContext)messageContext;
        String responseType = authenticationContext.getInitialAuthenticationRequest()
                .getParameter(OAuth.OAUTH_RESPONSE_TYPE);
        if(responseType != null) {
            return true;
        }
        return false;
    }

    @Override
    public FrameworkHandlerResponse validate(AuthenticationContext messageContext)
            throws RequestHandlerException {

        String clientId = ((OAuth2AuthzRequest)messageContext.getInitialAuthenticationRequest()).getClientId();
        String tenantDomain = messageContext.getInitialAuthenticationRequest().getTenantDomain();

        ServiceProvider serviceProvider = null;
        // Validate clientId, redirect_uri, response_type allowed

        messageContext.addParameter(OAuth2.OAUTH2_SERVICE_PROVIDER, serviceProvider);

        return FrameworkHandlerResponse.CONTINUE;
    }
}
