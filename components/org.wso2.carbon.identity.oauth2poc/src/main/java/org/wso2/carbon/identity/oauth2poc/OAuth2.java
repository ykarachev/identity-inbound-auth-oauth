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

package org.wso2.carbon.identity.oauth2poc;

public class OAuth2 {

    public static final long UNASSIGNED_VALIDITY_PERIOD = -1l;

    public class Header {
        public static final String CACHE_CONTROL = "Cache-Control";
        public static final String PRAGMA = "Pragma";
    }

    public class HeaderValue {
        public static final String CACHE_CONTROL_NO_STORE = "no-store";
        public static final String PRAGMA_NO_CACHE = "no-cache";
    }

    public static final String CONSENT = "consent";
    public static final String LOGGED_IN_USER = "loggedInUser";
    public static final String SESSION_DATA_KEY_CONSENT = "sessionDataKeyConsent";

    public static final String OAUTH2_SERVICE_PROVIDER = "OAuth2ServiceProvider";
    public static final String OAUTH2_RESOURCE_OWNER_AUTHN_REQUEST = "OAuth2ResourceOwnerAuthnRequest";
    public static final String OAUTH2_RESOURCE_OWNER_AUTHZ_REQUEST = "OAuth2ResourceOwnerAuthzRequest";
    public static final String PREV_ACCESS_TOKEN = "PreviousAccessToken";
}
