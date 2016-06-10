/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * you may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oidc.dcr;

import org.wso2.carbon.identity.oauth.dcr.DCRException;

/**
 * Custom exception to be thrown inside DynamicClientRegistration related functionality.
 */
public class OIDCDCRException extends DCRException {

    private static final long serialVersionUID = -3151279311929070297L;

    private String errorMessage;

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public OIDCDCRException(String msg, Exception nestedEx) {
        super(msg, nestedEx);
        setErrorMessage(msg);
    }

    public OIDCDCRException(String message, Throwable cause) {
        super(message, cause);
        setErrorMessage(message);
    }

    public OIDCDCRException(String msg) {
        super(msg);
        setErrorMessage(msg);
    }

    public OIDCDCRException(String message, String errorMessage) {
        super(message);
        this.errorMessage = errorMessage;
    }

    public OIDCDCRException(String message, Throwable cause, String errorMessage) {
        super(message, cause);
        this.errorMessage = errorMessage;
    }
}
