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

package org.wso2.carbon.identity.oidc.handler.response;

import com.nimbusds.jwt.JWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.framework.IdentityMessageContext;
import org.wso2.carbon.identity.framework.authentication.context.AuthenticationContext;
import org.wso2.carbon.identity.framework.authentication.processor.request.AuthenticationRequest;
import org.wso2.carbon.identity.oauth2poc.bean.message.request.authz.OAuth2AuthzRequest;
import org.wso2.carbon.identity.oauth2poc.bean.message.response.authz.AuthzResponse;
import org.wso2.carbon.identity.oauth2poc.exception.OAuth2InternalException;
import org.wso2.carbon.identity.oauth2poc.handler.response.TokenResponseHandler;
import org.wso2.carbon.identity.oauth2poc.util.OAuth2Util;
import org.wso2.carbon.identity.oidc.OIDC;
import org.wso2.carbon.identity.oidc.bean.message.request.authz.OIDCAuthzRequest;
import org.wso2.carbon.identity.oidc.handler.OIDCHandlerManager;

import java.util.Set;

public class OIDCTokenResponseHandler extends TokenResponseHandler {

    private static Log log = LogFactory.getLog(OIDCTokenResponseHandler.class);

    public String getName() {
        return "OIDCTokenResponseHandler";
    }

    public boolean canHandle(AuthenticationContext messageContext) {
        if(super.canHandle(messageContext)) {
            OAuth2AuthzRequest initialAuthenticationRequest= (OAuth2AuthzRequest)messageContext.getInitialAuthenticationRequest();
            Set<String> scopes = initialAuthenticationRequest.getScopes();
            if (scopes.contains(OIDC.OPENID_SCOPE)) {
                return true;
            }
        }
        return false;
    }

    protected AuthzResponse.AuthzResponseBuilder buildAuthzResponse(AuthenticationContext messageContext) {

        AuthzResponse.AuthzResponseBuilder builder = super.buildAuthzResponse(messageContext);
        OIDCAuthzRequest authzRequest = (OIDCAuthzRequest)messageContext.getInitialAuthenticationRequest();
        if(authzRequest.getResponseType().contains("id_token")) {
            try {
                addIDToken(builder, messageContext);
            } catch (OAuth2InternalException e) {
                log.error("Error occurred while building IDToken", e);
            }
        }
        return builder;
    }

    protected void addIDToken(AuthzResponse.AuthzResponseBuilder builder, AuthenticationContext messageContext)
            throws OAuth2InternalException {

        JWT jwt = OIDCHandlerManager.getInstance().buildIDToken(messageContext);
        String idToken = jwt.serialize();
        builder.getBuilder().setParam("id_token", idToken);
    }

}
