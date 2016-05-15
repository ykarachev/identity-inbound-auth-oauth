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

package org.wso2.carbon.identity.oidc.processor.authz;

import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundConstants;
import org.wso2.carbon.identity.oauth2new.processor.authz.AuthzProcessor;
import org.wso2.carbon.identity.oauth2new.util.OAuth2Util;
import org.wso2.carbon.identity.oidc.OIDC;
import org.wso2.carbon.identity.oidc.bean.message.request.authz.OIDCAuthzRequest;

import java.util.Set;

/*
 * InboundRequestProcessor for OAuth2 Authorization Endpoint
 */
public class OIDCAuthzProcessor extends AuthzProcessor {

    @Override
    public String getName() {
        return "OIDCAuthzProcessor";
    }

    public int getPriority() {
        return 0;
    }

    public String getCallbackPath(IdentityMessageContext context) {
        return null;
    }

    public String getRelyingPartyId() {
        return null;
    }

    public boolean canHandle(IdentityRequest identityRequest) {
        if(super.canHandle(identityRequest)) {
            Set<String> scopes = OAuth2Util.buildScopeSet(identityRequest.getParameter(OAuth.OAUTH_SCOPE));
            if (scopes.contains(OIDC.OPENID_SCOPE)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Initiate the request to authenticate resource owner
     *
     * @param messageContext The runtime message context
     * @return OAuth2 authorization endpoint
     */
    protected IdentityResponse.IdentityResponseBuilder buildResponseForFrameworkLogin(IdentityMessageContext messageContext) {

        boolean isLoginRequired = ((OIDCAuthzRequest)messageContext.getRequest()).isLoginRequired();
        messageContext.addParameter(InboundConstants.ForceAuth, isLoginRequired);
        boolean isPromptNone = ((OIDCAuthzRequest)messageContext.getRequest()).isPromptNone();
        messageContext.addParameter(InboundConstants.PassiveAuth, isPromptNone);
        return buildResponseForFrameworkLogin(messageContext);
    }

}
