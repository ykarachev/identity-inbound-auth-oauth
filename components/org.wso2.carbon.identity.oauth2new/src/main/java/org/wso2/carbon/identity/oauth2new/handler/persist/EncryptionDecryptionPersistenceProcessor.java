/*
 *Copyright (c) 2005-2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *WSO2 Inc. licenses this file to you under the Apache License,
 *Version 2.0 (the "License"); you may not use this file except
 *in compliance with the License.
 *You may obtain a copy of the License at
 *
 *http://www.apache.org/licenses/LICENSE-2.0
 *
 *Unless required by applicable law or agreed to in writing,
 *software distributed under the License is distributed on an
 *"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *KIND, either express or implied.  See the License for the
 *specific language governing permissions and limitations
 *under the License.
 */

package org.wso2.carbon.identity.oauth2new.handler.persist;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.bean.context.MessageContext;

/**
 * Stores encrypted tokens in the database.
 */
public class EncryptionDecryptionPersistenceProcessor extends TokenPersistenceProcessor {

    protected Log log = LogFactory.getLog(EncryptionDecryptionPersistenceProcessor.class);

    @Override
    public String getName() {
        return "EncryptionDecryptionPersistenceProcessor";
    }

    @Override
    public boolean canHandle(MessageContext messageContext) {
        return false;
    }

    @Override
    public String getProcessedClientId(String clientId) {
        return null;
    }

    @Override
    public String getPreprocessedClientId(String processedClientId) {
        return null;
    }

    @Override
    public String getProcessedClientSecret(String clientSecret) {
        return null;
    }

    @Override
    public String getPreprocessedClientSecret(String processedClientSecret) {
        return null;
    }

    @Override
    public String getProcessedAuthzCode(String authzCode) {
        return null;
    }

    @Override
    public String getPreprocessedAuthzCode(String processedAuthzCode) {
        return null;
    }

    @Override
    public String getProcessedAccessToken(String accessToken) {
        return null;
    }

    @Override
    public String getPreprocessedAccessToken(String processedAccessToken) {
        return null;
    }

    @Override
    public String getProcessedRefreshToken(String refreshToken) {
        return null;
    }

    @Override
    public String getPreprocessedRefreshToken(String processedRefreshToken) {
        return null;
    }
}
