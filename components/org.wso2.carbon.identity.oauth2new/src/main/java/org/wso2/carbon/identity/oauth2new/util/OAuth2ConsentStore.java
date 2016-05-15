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

package org.wso2.carbon.identity.oauth2new.util;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.dao.OpenIDUserRPDAO;
import org.wso2.carbon.identity.core.model.OpenIDUserRPDO;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.core.UserCoreConstants;

/**
 * Stores user consent on OIDC applications
 */
public class OAuth2ConsentStore {

    private static volatile OAuth2ConsentStore store = new OAuth2ConsentStore();

    private OAuth2ConsentStore() {

    }

    public static OAuth2ConsentStore getInstance() {
        return store;
    }

    public void approveAppAlways(AuthenticatedUser user, String spName, boolean trustedAlways) {

        if(user == null){
            throw new IllegalArgumentException("User is NULL");
        }
        if(StringUtils.isBlank(spName)){
            throw new IllegalArgumentException("Service Provider name is NULL");
        }
        OpenIDUserRPDO openIDUserRPDO = new OpenIDUserRPDO();
        openIDUserRPDO.setDefaultProfileName(UserCoreConstants.DEFAULT_PROFILE);
        openIDUserRPDO.setRpUrl(spName);
        openIDUserRPDO.setUserName(user.getAuthenticatedSubjectIdentifier());
        openIDUserRPDO.setTrustedAlways(trustedAlways);
        int tenantId = IdentityTenantUtil.getTenantId(user.getTenantDomain());
        OpenIDUserRPDAO dao = new OpenIDUserRPDAO();
        dao.createOrUpdate(openIDUserRPDO, tenantId);
    }

    public boolean hasUserApprovedAppAlways(AuthenticatedUser user, String appName) {

        OpenIDUserRPDAO dao = new OpenIDUserRPDAO();
        OpenIDUserRPDO openIDUserRPDO;
        int tenantId = IdentityTenantUtil.getTenantId(user.getTenantDomain());
        openIDUserRPDO = dao.getOpenIDUserRP(user.getAuthenticatedSubjectIdentifier(), appName, tenantId);
        if (openIDUserRPDO != null && openIDUserRPDO.isTrustedAlways()) {
            return true;
        }

        return false;
    }
}
