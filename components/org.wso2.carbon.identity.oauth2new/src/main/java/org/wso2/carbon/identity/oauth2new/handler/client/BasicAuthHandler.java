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

package org.wso2.carbon.identity.oauth2new.handler.client;

import org.apache.axiom.util.base64.Base64Utils;
import org.apache.commons.io.Charsets;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.oauth2new.common.ClientType;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2RuntimeException;

public class BasicAuthHandler extends ClientAuthHandler {

    @Override
    public String getName() {
        return "BasicAuthHandler";
    }

    @Override
    public boolean canHandle(MessageContext messageContext) {
        return true;
    }

    @Override
    public ClientType clientType(OAuth2MessageContext messageContext) {
        return ClientType.CONFIDENTIAL;
    }

    @Override
    public String authenticate(OAuth2MessageContext messageContext) {
        String authzHeader = messageContext.getRequest().getHeaderMap().get(OAuth.HeaderType.AUTHORIZATION);
        String clientId = null;
        if(StringUtils.isNotBlank(authzHeader)) {
            String[] splitValues = authzHeader.trim().split(" ");
            if (splitValues.length == 2) {
                byte[] decodedBytes = Base64Utils.decode(splitValues[1].trim());
                if (ArrayUtils.isNotEmpty(decodedBytes)) {
                    String idSecret = new String(decodedBytes, Charsets.UTF_8);
                    String[] idSecretArray = idSecret.split(":");
                    if (idSecretArray.length == 2) {
                        clientId = idSecretArray[0];
                        String clientSecret = idSecretArray[1];
                        // Get OAuth2 data from application.mgt and validate
                        return "";
                    }

                }
            }
        }
        StringBuffer message = new StringBuffer("Unauthenticated Client");
        if(StringUtils.isNotBlank(clientId)){
            message.append(" ").append(clientId);
        }
        throw OAuth2RuntimeException.error(message.toString());
    }
}
