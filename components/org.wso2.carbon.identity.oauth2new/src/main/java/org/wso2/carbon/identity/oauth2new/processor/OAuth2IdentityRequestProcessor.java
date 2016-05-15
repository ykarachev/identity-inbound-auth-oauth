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

package org.wso2.carbon.identity.oauth2new.processor;

import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2AuthzMessageContext;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2TokenMessageContext;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2RuntimeException;

public abstract class OAuth2IdentityRequestProcessor extends IdentityProcessor {

    /**
     * Tells if refresh token must be issued or not for this access token request.
     *
     * @param messageContext The runtime message context
     * @return {@code true} if refresh tokens must be issued
     */
    public boolean issueRefreshToken(OAuth2MessageContext messageContext) {

        if(messageContext instanceof OAuth2AuthzMessageContext){
            return issueRefreshToken((OAuth2AuthzMessageContext) messageContext);
        } else if(messageContext instanceof OAuth2TokenMessageContext) {
            return issueRefreshToken((OAuth2TokenMessageContext) messageContext);
        } else {
            throw OAuth2RuntimeException.error("Invalid OAuth2MessageContext; neither of type " +
                                               "OAuth2AuthzMessageContext nor type OAuth2TokenMessageContext");
        }
    }

    /**
     * Tells if refresh token must be issued or not for this access token request to the authorization endpoint.
     *
     * @param messageContext The runtime authorization message context
     * @return {@code true} if refresh tokens must be issued
     */
    protected boolean issueRefreshToken(OAuth2AuthzMessageContext messageContext) {
        return false;
    }

    /**
     * Tells if refresh token must be issued or not for this access token request to the token endpoint.
     *
     * @param messageContext The runtime token message context
     * @return {@code true} if refresh tokens must be issued
     */
    protected boolean issueRefreshToken(OAuth2TokenMessageContext messageContext) {

        if(GrantType.CLIENT_CREDENTIALS.toString().equals(messageContext.getRequest().getGrantType())) {
            return false;
        }
        return true;
    }



}
