/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.oauth.scope.endpoint.util;

import org.apache.commons.logging.Log;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth.scope.endpoint.Constants;
import org.wso2.carbon.identity.oauth.scope.endpoint.Exceptions.BadRequestException;
import org.wso2.carbon.identity.oauth.scope.endpoint.Exceptions.ConflictException;
import org.wso2.carbon.identity.oauth.scope.endpoint.Exceptions.InternalServerErrorException;
import org.wso2.carbon.identity.oauth.scope.endpoint.dto.ErrorDTO;
import org.wso2.carbon.identity.oauth.scope.endpoint.dto.ScopeDTO;

public class ScopeUtils {

    /**
     * Logs the error, builds a internalServerErrorException with specified details and throws it
     *
     * @param msg error message
     * @param log Log instance
     * @throws InternalServerErrorException
     */
    public static void handleInternalServerError(String msg, String code, Log log, Throwable throwable)
            throws InternalServerErrorException {
        InternalServerErrorException internalServerErrorException = buildInternalServerErrorException(code);
        if (throwable == null) {
            log.error(msg);
        } else {
            log.error(msg, throwable);
        }
        throw internalServerErrorException;
    }


    /**
     * Returns a new InternalServerErrorException
     *
     * @return a new InternalServerErrorException with default details as a response DTO
     */
    public static InternalServerErrorException buildInternalServerErrorException(String code) {
        ErrorDTO errorDTO = getErrorDTO(Constants.STATUS_INTERNAL_SERVER_ERROR_MESSAGE_DEFAULT, code,
                Constants.STATUS_INTERNAL_SERVER_ERROR_DESCRIPTION_DEFAULT);
        return new InternalServerErrorException(errorDTO);
    }


    /**
     * Logs the error, builds a BadRequestException with specified details and throws it
     *
     * @param msg  error message
     * @param code error code
     * @throws BadRequestException
     */
    public static void handleBadRequest(String msg, String code) throws BadRequestException {
        BadRequestException badRequestException = buildBadRequestException(msg, code);
        throw badRequestException;
    }

    /**
     * Returns a new BadRequestException
     *
     * @param description description of the exception
     * @return a new BadRequestException with the specified details as a response DTO
     */
    public static BadRequestException buildBadRequestException(String description, String code) {
        ErrorDTO errorDTO = getErrorDTO(Constants.STATUS_BAD_REQUEST_MESSAGE_DEFAULT, code, description);
        return new BadRequestException(errorDTO);
    }

    /**
     * Logs the error, builds a ConflictException with specified details and throws it
     *
     * @param msg  error message
     * @param code error code
     * @throws ConflictException
     */
    public static void handleConflict(String msg, String code) throws ConflictException {
        ConflictException conflictException = buildConflictException(msg, code);
        throw conflictException;
    }

    /**
     * Returns a new ConflictException
     *
     * @param description description of the exception
     * @return a new ConflictException with the specified details as a response DTO
     */
    public static ConflictException buildConflictException(String description, String code) {
        ErrorDTO errorDTO = getErrorDTO(Constants.STATUS_CONFLICT_MESSAGE_DEFAULT, code, description);
        return new ConflictException(errorDTO);
    }

    /**
     * Returns a generic errorDTO
     *
     * @param message specifies the error message
     * @return A generic errorDTO with the specified details
     */
    public static ErrorDTO getErrorDTO(String message, String code, String description) {
        ErrorDTO errorDTO = new ErrorDTO();
        errorDTO.setCode(code);
        errorDTO.setMessage(message);
        errorDTO.setDescription(description);
        return errorDTO;
    }

    public static Scope getScope(ScopeDTO scopeDTO) {

        return new Scope(
                scopeDTO.getId(),
                scopeDTO.getName(),
                scopeDTO.getDescription(),
                scopeDTO.getBindings());
    }
}
