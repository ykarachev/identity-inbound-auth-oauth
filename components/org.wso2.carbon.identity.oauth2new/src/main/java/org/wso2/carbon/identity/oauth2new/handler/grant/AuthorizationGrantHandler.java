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

import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2TokenMessageContext;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2ClientException;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception;

/*
 * To authenticate OAuth2 clients
 */
public class AuthorizationGrantHandler extends AbstractIdentityHandler {

    @Override
    public String getName() {
        return "AuthorizationGrantHandler";
    }

    /**
     * Validate the authorization grant.
     *
     * @param messageContext The runtime message context
     * @return Returns the client type - confidential or public.
     */
    public void validateGrant(OAuth2TokenMessageContext messageContext) throws OAuth2ClientException, OAuth2Exception {

        // validate with registered grant types for the application
    }
}
