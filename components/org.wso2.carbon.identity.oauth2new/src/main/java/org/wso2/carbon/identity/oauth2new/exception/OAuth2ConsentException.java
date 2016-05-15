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

package org.wso2.carbon.identity.oauth2new.exception;

public class OAuth2ConsentException extends OAuth2Exception {

    protected OAuth2ConsentException(String errorDescription) {
        super(errorDescription);
    }

    protected OAuth2ConsentException(String errorDescription, Throwable cause) {
        super(errorDescription, cause);
    }

    public static OAuth2ConsentException error(String errorDescription){
        return new OAuth2ConsentException(errorDescription);
    }

    public static OAuth2ConsentException error(String errorDescription, Throwable cause){
        return new OAuth2ConsentException(errorDescription, cause);
    }
}
