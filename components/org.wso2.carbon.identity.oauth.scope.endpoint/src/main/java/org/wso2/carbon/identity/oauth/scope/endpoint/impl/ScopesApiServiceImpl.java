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

package org.wso2.carbon.identity.oauth.scope.endpoint.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.scope.endpoint.ApiResponseMessage;
import org.wso2.carbon.identity.oauth.scope.endpoint.Constants;
import org.wso2.carbon.identity.oauth.scope.endpoint.ScopesApiService;
import org.wso2.carbon.identity.oauth.scope.endpoint.dto.ScopeDTO;
import org.wso2.carbon.identity.oauth.scope.endpoint.util.ScopeUtils;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeException;
import org.wso2.carbon.identity.oauth2.OAuth2ScopeService;
import org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants;
import org.wso2.carbon.identity.oauth2.bean.Scope;

import javax.ws.rs.core.Response;
import java.util.Set;

/**
 * ScopesApiService is service exposed for the REST endpoint used to handling scope bindings
 */
public class ScopesApiServiceImpl extends ScopesApiService {
    private static final Log LOG = LogFactory.getLog(ScopesApiServiceImpl.class);
    private static final OAuth2ScopeService oAuth2ScopeService = new OAuth2ScopeService();

    /**
     * Delete the scope for the given scope ID
     *
     * @param scopeId Scope ID of the scope which need to get deleted
     * @return Response with the status of scope deletion by scope ID
     */
    @Override
    public Response deleteScopeByID(String scopeId) {
        try {
            oAuth2ScopeService.deleteScopeByID(scopeId);
        } catch (IdentityOAuth2ScopeClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client Error while deleting scope by ID '%s'. " + scopeId, e);
            }
            ScopeUtils.handleBadRequest(e.getMessage(), e.getErrorCode());

        } catch (IdentityOAuth2ScopeException e) {
            ScopeUtils.handleInternalServerError(Constants.SERVER_ERROR, e.getErrorCode(), LOG, e);
        } catch (Throwable throwable) {
            ScopeUtils.handleInternalServerError(Constants.SERVER_ERROR, Oauth2ScopeConstants
                    .ErrorMessages.ERROR_CODE_UNEXPECTED.getCode(), LOG, throwable);
        }

        return Response.status(Response.Status.OK).entity(new ApiResponseMessage(ApiResponseMessage.OK,
                "Successfully deleted scope by ID " + scopeId)).build();
    }

    /**
     * Retrieve the scope of the given scope ID
     *
     * @param scopeId Scope ID of the scope which need to get retrieved
     * @return Response with the retrieved scope/ retrieval status for the given scope ID
     */
    @Override
    public Response getScopeByID(String scopeId) {
        Scope scope = null;

        try {
            scope = oAuth2ScopeService.getScopeByID(scopeId);
        } catch (IdentityOAuth2ScopeClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client Error while get scope by ID. ", e);
            }
            ScopeUtils.handleBadRequest(e.getMessage(), e.getErrorCode());

        } catch (IdentityOAuth2ScopeException e) {
            ScopeUtils.handleInternalServerError(Constants.SERVER_ERROR, e.getErrorCode(), LOG, e);
        } catch (Throwable throwable) {
            ScopeUtils.handleInternalServerError(Constants.SERVER_ERROR, Oauth2ScopeConstants
                    .ErrorMessages.ERROR_CODE_UNEXPECTED.getCode(), LOG, throwable);
        }

        return Response.ok(scope).build();
    }

    /**
     * Retrieve the available scope list
     *
     * @param filter     Filter the scope list
     * @param startIndex Start Index of the result set to enforce pagination
     * @param count      Number of elements in the result set to enforce pagination
     * @param sortBy     Sort the result set based on this attribute
     * @param sortOrder  Sort order
     * @return Response with the retrieved scopes/ retrieval status
     */
    @Override
    public Response getScopes(String filter, Integer startIndex, Integer count, String sortBy, String sortOrder) {
        Set<Scope> scopes = null;

        try {
            scopes = oAuth2ScopeService.getScopes(filter, startIndex, count, sortBy, sortOrder);
        } catch (IdentityOAuth2ScopeClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client Error while getting available scopes. ", e);
            }
            ScopeUtils.handleBadRequest(e.getMessage(), e.getErrorCode());

        } catch (IdentityOAuth2ScopeException e) {
            ScopeUtils.handleInternalServerError(Constants.SERVER_ERROR, e.getErrorCode(), LOG, e);
        } catch (Throwable throwable) {
            ScopeUtils.handleInternalServerError(Constants.SERVER_ERROR, Oauth2ScopeConstants
                    .ErrorMessages.ERROR_CODE_UNEXPECTED.getCode(), LOG, throwable);
        }
        return Response.ok(scopes).build();
    }

    /**
     * Check the existence of a scope
     *
     * @param scopeName Name of the scope
     * @return Response with the indication whether the scope exists or not
     */
    @Override
    public Response isScopeExists(String scopeName) {
        boolean isScopeExists = false;

        try {
            isScopeExists = oAuth2ScopeService.isScopeExists(scopeName);
        } catch (IdentityOAuth2ScopeClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client Error while get scope existence. ", e);
            }
            ScopeUtils.handleBadRequest(e.getMessage(), e.getErrorCode());

        } catch (IdentityOAuth2ScopeException e) {
            ScopeUtils.handleInternalServerError(Constants.SERVER_ERROR, e.getErrorCode(), LOG, e);
        } catch (Throwable throwable) {
            ScopeUtils.handleInternalServerError(Constants.SERVER_ERROR, Oauth2ScopeConstants
                    .ErrorMessages.ERROR_CODE_UNEXPECTED.getCode(), LOG, throwable);
        }

        if (isScopeExists) {
            return Response.status(Response.Status.OK).entity(new ApiResponseMessage(ApiResponseMessage.OK,
                    "Scope Exists for the name " + scopeName)).build();
        }

        return Response.status(Response.Status.NOT_FOUND).entity(new ApiResponseMessage(ApiResponseMessage.OK,
                "Scope doesn't exist for the name " + scopeName)).build();
    }

    /**
     * Register a scope with the bindings
     *
     * @param scope details of the scope to be registered
     * @return Response with the status of the registration
     */
    @Override
    public Response registerScope(ScopeDTO scope) {
        Scope registeredScope = null;
        try {
            registeredScope = oAuth2ScopeService.registerScope(ScopeUtils.getScope(scope));
        } catch (IdentityOAuth2ScopeClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client Error while registering scope ", e);
            }
            if (Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_CONFLICT_REQUEST_EXISTING_SCOPE.getCode().equals(e.getErrorCode())) {
                ScopeUtils.handleConflict(e.getMessage(), e.getErrorCode());
            } else {
                ScopeUtils.handleBadRequest(e.getMessage(), e.getErrorCode());
            }

        } catch (IdentityOAuth2ScopeException e) {
            ScopeUtils.handleInternalServerError(Constants.SERVER_ERROR, e.getErrorCode(), LOG, e);
        } catch (Throwable throwable) {
            ScopeUtils.handleInternalServerError(Constants.SERVER_ERROR, Oauth2ScopeConstants
                    .ErrorMessages.ERROR_CODE_UNEXPECTED.getCode(), LOG, throwable);
        }
        return Response.status(Response.Status.CREATED).entity(registeredScope).build();
    }

    /**
     * Update a scope
     *
     * @param scope   details of the scope to be updated
     * @param scopeId scope ID of the scope to be updated
     * @return
     */
    @Override
    public Response updateScopeByID(ScopeDTO scope, String scopeId) {
        try {
            oAuth2ScopeService.updateScopeByID(ScopeUtils.getScope(scope), scopeId);
        } catch (IdentityOAuth2ScopeClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client Error while updating scope by ID '%s'. " + scopeId, e);
            }
            ScopeUtils.handleBadRequest(e.getMessage(), e.getErrorCode());

        } catch (IdentityOAuth2ScopeException e) {
            ScopeUtils.handleInternalServerError(Constants.SERVER_ERROR, e.getErrorCode(), LOG, e);
        } catch (Throwable throwable) {
            ScopeUtils.handleInternalServerError(Constants.SERVER_ERROR, Oauth2ScopeConstants
                    .ErrorMessages.ERROR_CODE_UNEXPECTED.getCode(), LOG, throwable);
        }

        return Response.status(Response.Status.OK).entity(new ApiResponseMessage(ApiResponseMessage.OK,
                "Successfully updated scope by ID " + scopeId)).build();
    }

}
