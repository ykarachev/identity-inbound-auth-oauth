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

package org.wso2.carbon.identity.oauth2;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.cache.OauthScopeCache;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.dao.ScopeMgtDAO;
import org.wso2.carbon.identity.oauth2.util.Oauth2ScopeUtils;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * OAuth2ScopeService use for scope handling
 */
public class OAuth2ScopeService {
    //TODO get the instance inside the constructor
    private static ScopeMgtDAO scopeMgtDAO;
    private OauthScopeCache scopeCache = OauthScopeCache.getInstance();
    private static final Log log = LogFactory.getLog(OAuth2ScopeService.class);

    public OAuth2ScopeService() {
        scopeMgtDAO = ScopeMgtDAO.getInstance();
    }

    /**
     * Register a scope with the bindings
     *
     * @param scope details of the scope to be registered
     * @throws IdentityOAuth2ScopeException
     */
    public Scope registerScope(Scope scope) throws IdentityOAuth2ScopeException {
        int tenantID = Oauth2ScopeUtils.getTenantID();

        // check whether the scope name is provided
        if (StringUtils.isBlank(scope.getName())) {
            throw Oauth2ScopeUtils.handleClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_BAD_REQUEST_SCOPE_NAME, null);
        }

        // check whether the scope description is provided
        if (StringUtils.isBlank(scope.getDescription())) {
            throw Oauth2ScopeUtils.handleClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_BAD_REQUEST_SCOPE_DESCRIPTION, null);
        }
        try {
            // check whether a scope exists with the provided scope name
            String existingScopeID = scopeMgtDAO.getScopeIDByName(scope.getName(), tenantID);
            if (existingScopeID != null) {
                throw Oauth2ScopeUtils.handleClientException(Oauth2ScopeConstants.ErrorMessages.
                        ERROR_CODE_CONFLICT_REQUEST_EXISTING_SCOPE, scope.getName());
            }
        } catch (IdentityOAuth2Exception e) {
            throw Oauth2ScopeUtils.handleServerException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_FAILED_TO_GET_SCOPE_BY_KEY, null, e);
        }

        String scopeID = UUID.randomUUID().toString();
        scope.setId(scopeID);

        try {
            scopeMgtDAO.addScope(scope, tenantID);
            if (log.isDebugEnabled()) {
                log.debug("Scope is added to the database.");
            }
        } catch (IdentityOAuth2Exception e) {
            throw Oauth2ScopeUtils.handleServerException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_FAILED_TO_REGISTER_SCOPE, null, e);
        }
        if (OAuthServerConfiguration.getInstance().isCacheEnabled()) {
            scopeCache.addToCache(scopeID, scope);
            if (log.isDebugEnabled()) {
                log.debug("Scope is added to the cache.");
            }
        }
        return scope;
    }

    /**
     * Retrieve the available scope list
     *
     * @param filter     Filter the scope list
     * @param startIndex Start Index of the result set to enforce pagination
     * @param count      Number of elements in the result set to enforce pagination
     * @param sortBy     Sort the result set based on this attribute
     * @param sortOrder  Sort order
     * @return Scope list
     * @throws IdentityOAuth2ScopeException
     */
    public Set<Scope> getScopes(String filter, Integer startIndex, Integer count, String sortBy, String sortOrder)
            throws IdentityOAuth2ScopeException {
        Set<Scope> scopes = new HashSet<>();

        // check for no query params.
        if (sortOrder == null && sortBy == null && filter == null && startIndex == null && count == null) {
            try {
                scopes = scopeMgtDAO.getAllScopes(Oauth2ScopeUtils.getTenantID());
            } catch (IdentityOAuth2Exception e) {
                throw Oauth2ScopeUtils.handleServerException(Oauth2ScopeConstants.ErrorMessages.
                        ERROR_CODE_FAILED_TO_GET_ALL_SCOPES, null, e);
            }
        }

        else if (sortOrder != null && sortBy != null) {
            throw Oauth2ScopeUtils.handleServerException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_SORTING_NOT_SUPPORTED, "");
        }
        // check if it is a pagination and filter combination.
        else if (filter != null) {
            scopes = listUsersWithPaginationAndFilter(filter, startIndex, count);
        }
        //check if it is a pagination only request.
        else if (filter == null) {
            scopes = listUsersWithPagination(startIndex, count);

        } else {
            throw Oauth2ScopeUtils.handleClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_BAD_REQUEST_NOT_SUPPORTED_LIST_PARAM, null);

        }
        return scopes;
    }

    /**
     *
     * @param scopeID Scope ID of the scope which need to get retrieved
     * @return Retrieved Scope
     * @throws IdentityOAuth2ScopeException
     */
    public Scope getScopeByID(String scopeID) throws IdentityOAuth2ScopeException {
        Scope scope;
        Scope scopeFromCache = null;

        if (scopeID == null) {
            throw Oauth2ScopeUtils.handleClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_BAD_REQUEST_SCOPE_ID, null);
        }

        if (OAuthServerConfiguration.getInstance().isCacheEnabled()) {
            scopeFromCache = scopeCache.getValueFromCache(scopeID);
        }
        if(scopeFromCache == null) {
            try {
                scope = scopeMgtDAO.getScopeByID(scopeID, Oauth2ScopeUtils.getTenantID());
                scopeCache.addToCache(scopeID, scope);
                if (log.isDebugEnabled()) {
                    log.debug("Scope is added to the cache.");
                }

            } catch (IdentityOAuth2Exception e) {
                throw Oauth2ScopeUtils.handleServerException(Oauth2ScopeConstants.ErrorMessages.
                        ERROR_CODE_FAILED_TO_GET_SCOPE_BY_KEY, null, e);
            }
        } else {
            scope = scopeFromCache;
            if (log.isDebugEnabled()) {
                log.debug("Scope is getting from the cache.");
            }
        }

        if (scope == null) {
            throw Oauth2ScopeUtils.handleClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_BAD_REQUEST_SCOPE_ID, null);
        }

        return scope;
    }

    /**
     * Check the existence of a scope
     *
     * @param scopeName Name of the scope
     * @return true if scope with the given scope name exists
     * @throws IdentityOAuth2ScopeException
     */
    public boolean isScopeExists(String scopeName) throws IdentityOAuth2ScopeException {
        String scopeID;
        boolean isScopeExists = false;

        if (scopeName == null) {
            throw Oauth2ScopeUtils.handleClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_BAD_REQUEST_SCOPE_NAME, null);
        }
        try {
            scopeID = scopeMgtDAO.getScopeIDByName(scopeName, Oauth2ScopeUtils.getTenantID());
        } catch (IdentityOAuth2Exception e) {
            throw Oauth2ScopeUtils.handleServerException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_FAILED_TO_GET_SCOPE_BY_KEY, null, e);
        }

        if (scopeID != null) {
            isScopeExists = true;
        }

        return isScopeExists;
    }

    /**
     * Delete the scope for the given scope ID
     *
     * @param scopeID Scope ID of the scope which need to get deleted
     * @throws IdentityOAuth2ScopeException
     */
    public void deleteScopeByID(String scopeID) throws IdentityOAuth2ScopeException {
        if (scopeID == null) {
            throw Oauth2ScopeUtils.handleClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_BAD_REQUEST_SCOPE_ID, null);
        }

        try {
            scopeMgtDAO.deleteScopeByID(scopeID, Oauth2ScopeUtils.getTenantID());
        } catch (IdentityOAuth2Exception e) {
            throw Oauth2ScopeUtils.handleServerException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_FAILED_TO_DELETE_SCOPE_BY_ID, scopeID, e);
        }
        if (OAuthServerConfiguration.getInstance().isCacheEnabled()) {
            scopeCache.clearCacheEntry(scopeID);
            if (log.isDebugEnabled()) {
                log.debug("Scope is deleted from the cache.");
            }
        }
    }

    /**
     * Update the scope of the given scope ID
     *
     * @param updatedScope details of updated scope
     * @param scopeID Scope ID of the scope which need to get updated
     * @throws IdentityOAuth2ScopeException
     */
    public void updateScopeByID(Scope updatedScope, String scopeID) throws IdentityOAuth2ScopeException {
        if (scopeID == null) {
            throw Oauth2ScopeUtils.handleClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_BAD_REQUEST_SCOPE_ID, null);
        }

        try {
            updatedScope.setId(scopeID);
            scopeMgtDAO.updateScopeByID(updatedScope, Oauth2ScopeUtils.getTenantID());
        } catch (IdentityOAuth2Exception e) {
            throw Oauth2ScopeUtils.handleServerException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_FAILED_TO_UPDATE_SCOPE_BY_ID, scopeID, e);
        }
        if (OAuthServerConfiguration.getInstance().isCacheEnabled()) {
            scopeCache.addToCache(scopeID, updatedScope);
            if (log.isDebugEnabled()) {
                log.debug("Scope is updated in the cache.");
            }
        }
    }

    /**
     * List scopes with pagination and filtering
     *
     * @param filterString     Filter the scope list
     * @param startIndex Start Index of the result set to enforce pagination
     * @param count      Number of elements in the result set to enforce pagination
     * @return List of available scopes
     * @throws IdentityOAuth2ScopeException
     */
    private Set<Scope> listUsersWithPaginationAndFilter(String filterString, Integer startIndex, Integer count)
            throws IdentityOAuth2ScopeException {
        Set<Scope> scopes;

        if (count == null || count < 0) {
            count = Oauth2ScopeConstants.MAX_FILTER_COUNT;
        }
        if (startIndex == null || startIndex < 1) {
            startIndex = 1;
        }
        // Database handles start index as 0
        if (startIndex > 0) {
            startIndex--;
        }

        String trimmedFilter = filterString.trim();
        //verify filter string. We currently support only equal operation
        if (!(trimmedFilter.contains("eq") || trimmedFilter.contains("Eq"))) {
            throw Oauth2ScopeUtils.handleClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_FAILED_TO_FILTER_INVALID_OPERATION, null);
        }
        String[] filterParts = null;
        if (trimmedFilter.contains("eq")) {
            filterParts = trimmedFilter.split("eq");
        } else if (trimmedFilter.contains("Eq")) {
            filterParts = trimmedFilter.split("Eq");
        }
        if (filterParts == null || filterParts.length != 2) {
            //filter query param is not properly splitted. Hence Throwing unsupported operation exception:400
            throw Oauth2ScopeUtils.handleClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_FAILED_TO_FILTER_UNRECOGNIZE_OPERATION, null);
        }

        String filterAttribute = filterParts[0].trim();
        String filterOperation = "eq";
        String filterValue = filterParts[1].trim();
        if (filterValue.charAt(0) == '\"') {
            filterValue = filterValue.substring(1, filterValue.length() - 1);
        }

        if (filterAttribute == null) {
            throw Oauth2ScopeUtils.handleClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_FAILED_TO_FILTER_UNRECOGNIZE_ATTRIBUTE, null);
        }

        if(filterAttribute.equals("name")) {
            filterAttribute = "NAME";
        } else {
            throw Oauth2ScopeUtils.handleClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_FAILED_TO_FILTER_UNRECOGNIZE_ATTRIBUTE, null);
        }


        try {
            scopes = scopeMgtDAO.getScopesWithPaginationAndFilter(filterAttribute, filterValue,startIndex, count, Oauth2ScopeUtils.getTenantID());
        } catch (IdentityOAuth2Exception e) {
            throw Oauth2ScopeUtils.handleServerException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_FAILED_TO_GET_ALL_SCOPES_PAGINATION, e);
        }
        return scopes;
    }

    /**
     * List scopes with filtering
     *
     * @param startIndex Start Index of the result set to enforce pagination
     * @param count      Number of elements in the result set to enforce pagination
     * @return List of available scopes
     * @throws IdentityOAuth2ScopeException
     */
    private Set<Scope> listUsersWithPagination(Integer startIndex, Integer count)
            throws IdentityOAuth2ScopeServerException {
        Set<Scope> scopes;

        if (count == null || count < 0) {
            count = Oauth2ScopeConstants.MAX_FILTER_COUNT;
        }
        if (startIndex == null || startIndex < 1) {
            startIndex = 1;
        }

        // Database handles start index as 0
        if (startIndex > 0) {
            startIndex--;
        }

        try {
            scopes = scopeMgtDAO.getScopesWithPagination(startIndex, count, Oauth2ScopeUtils.getTenantID());
        } catch (IdentityOAuth2Exception e) {
            throw Oauth2ScopeUtils.handleServerException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_FAILED_TO_GET_ALL_SCOPES_PAGINATION, e);
        }
        return scopes;
    }
}
