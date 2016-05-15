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

package org.wso2.carbon.identity.oauth2new.revoke;

import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2InternalException;

import java.util.Set;

public class OAuth2RevocationServiceImpl implements OAuth2RevocationService {

    private static volatile OAuth2RevocationService instance = new OAuth2RevocationServiceImpl();

    private OAuth2RevocationServiceImpl() {

    }

    public static OAuth2RevocationService getInstance() {
        return instance;
    }

    public Set<String> getAppsAuthorizedByUser(User user) throws OAuth2InternalException {
        return null;
    }

    public void revokeApplication(String application, String tenantDomain) throws OAuth2InternalException {

    }

}
