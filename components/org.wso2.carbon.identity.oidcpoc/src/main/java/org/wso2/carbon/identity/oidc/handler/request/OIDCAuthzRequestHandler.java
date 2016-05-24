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

package org.wso2.carbon.identity.oidc.handler.request;

import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.application.authentication.framework.FrameworkHandlerResponse;
import org.wso2.carbon.identity.application.authentication.framework.InboundConstants;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.processor.handler.request.RequestHandlerException;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.oauth2poc.handler.request.AuthzRequestHandler;
import org.wso2.carbon.identity.oauth2poc.util.OAuth2Util;
import org.wso2.carbon.identity.oidc.OIDC;
import org.wso2.carbon.identity.oidc.bean.message.request.authz.OIDCAuthzRequest;

import java.util.Set;

/*
 * InboundRequestProcessor for OAuth2 Authorization Endpoint
 */
public class OIDCAuthzRequestHandler extends AuthzRequestHandler {

    @Override
    public String getName() {
        return "OIDCAuthzRequestHandler";
    }


    public boolean canHandle(MessageContext messageContext) {
        if(super.canHandle(messageContext)) {
            String scope = ((AuthenticationContext) messageContext).getInitialAuthenticationRequest()
                    .getParameter(OAuth.OAUTH_SCOPE);
            Set<String> scopes = OAuth2Util.buildScopeSet(scope);
            if (scopes.contains(OIDC.OPENID_SCOPE)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public FrameworkHandlerResponse validate(AuthenticationContext messageContext)
            throws RequestHandlerException {

        boolean isLoginRequired = ((OIDCAuthzRequest)messageContext.getInitialAuthenticationRequest()).isLoginRequired();
        messageContext.addParameter(InboundConstants.ForceAuth, isLoginRequired);
        boolean isPromptNone = ((OIDCAuthzRequest)messageContext.getInitialAuthenticationRequest()).isPromptNone();
        messageContext.addParameter(InboundConstants.PassiveAuth, isPromptNone);

        return super.validate(messageContext);
    }

}
