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

package org.wso2.carbon.identity.oidc;

public class OIDC {

    public static final String OPENID_SCOPE = "openid";
    public static final String NONCE = "nonce";
    public static final String DISPLAY = "display";
    public static final String ID_TOKEN_HINT = "id_token_hint";
    public static final String LOGIN_HINT = "login_hint";
    public static final String PROMPT = "prompt";

    public static class Prompt {
        public static final String LOGIN = "login";
        public static final String CONSENT = "consent";
        public static final String NONE = "none";
    }
}
