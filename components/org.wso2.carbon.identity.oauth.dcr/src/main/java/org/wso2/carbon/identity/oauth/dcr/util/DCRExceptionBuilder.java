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
package org.wso2.carbon.identity.oauth.dcr.util;


import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.oauth.dcr.DCRRuntimeException;

import java.lang.reflect.InvocationTargetException;

public class DCRExceptionBuilder {
    public static <T extends IdentityException> T buildException(T exception, String errorCode, String errorDescription){
        IdentityException.ErrorInfo.ErrorInfoBuilder errorInfoBuilder = new IdentityException.ErrorInfo.ErrorInfoBuilder(errorDescription);
        errorInfoBuilder.errorCode(errorCode);
        exception.addErrorInfo(errorInfoBuilder.build());
        return exception;
    }

    public static <T extends IdentityException> T buildException(T exception, String errorCode, String errorDescription, String operationContext){
        IdentityException.ErrorInfo.ErrorInfoBuilder errorInfoBuilder = new IdentityException.ErrorInfo.ErrorInfoBuilder(errorDescription);
        errorInfoBuilder.errorCode(errorCode);
        errorInfoBuilder.parameter(DCRConstants.DCR_OPERATION_CONTEXT, operationContext);
        exception.addErrorInfo(errorInfoBuilder.build());
        return exception;
    }

    public static <T extends IdentityException> T buildException(Class<T> exceptionClass, String errorCode, String errorDescription) throws DCRRuntimeException {
        try {
            T exception = exceptionClass.getConstructor(String.class).newInstance(errorDescription);
            return buildException(exception, errorCode, errorDescription);
        } catch (Exception e) {
            throw new DCRRuntimeException("Error occurred while creating new instant using reflection, " + e.getMessage());
        }
    }

    public static <T extends IdentityException> T buildException(Class<T> exceptionClass, String errorCode, String errorDescription, String contextId) throws DCRRuntimeException {
        try {
            T exception = exceptionClass.getConstructor(String.class).newInstance(errorDescription);
            return buildException(exception, errorCode, errorDescription, contextId);
        } catch (Exception e) {
            throw new DCRRuntimeException("Error occurred while creating new instant using reflection, " + e.getMessage());
        }
    }

    public static <T extends IdentityException> T buildException(Class<T> exceptionClass, IdentityException.ErrorInfo errorInfo) throws DCRRuntimeException {
        try {
            T exception = exceptionClass.getConstructor(String.class).newInstance(errorInfo.getErrorDescription());
            exception.addErrorInfo(errorInfo);
            return exception ;
        } catch (Exception e) {
            throw new DCRRuntimeException("Error occurred while creating new instant using reflection, " + e.getMessage());
        }
    }
}
