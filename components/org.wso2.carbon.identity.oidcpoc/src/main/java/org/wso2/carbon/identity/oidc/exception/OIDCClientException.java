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

package org.wso2.carbon.identity.oidc.exception;

import org.wso2.carbon.identity.oauth2poc.exception.OAuth2ClientException;

public class OIDCClientException extends OAuth2ClientException {

    protected OIDCClientException(String errorDescription) {
        super(errorDescription);
    }

    protected OIDCClientException(String errorDescription, Throwable cause) {
        super(errorDescription, cause);
    }

    public static OIDCClientException error(String errorDescription){
        return new OIDCClientException(errorDescription);
    }

    public static OIDCClientException error(String errorDescription, Throwable cause){
        return new OIDCClientException(errorDescription, cause);
    }
}
