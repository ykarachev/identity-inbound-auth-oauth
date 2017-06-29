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

package org.wso2.carbon.identity.oauth2.dao;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.util.NamedPreparedStatement;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.List;
import java.util.ArrayList;
import java.util.Set;
import java.util.Map;
import java.util.HashMap;

/**
 * Data Access Layer functionality for Scope management. This includes storing, updating, deleting and retrieving scopes
 */
public class ScopeMgtDAO {

    private static final Log log = LogFactory.getLog(ScopeMgtDAO.class);

    private static final ScopeMgtDAO scopeMgtDAO = new ScopeMgtDAO();

    private ScopeMgtDAO() {
    }

    public static ScopeMgtDAO getInstance() {
        return scopeMgtDAO;
    }

    /**
     * Add a scope
     *
     * @param scope    Scope
     * @param tenantID tenant ID
     * @throws IdentityOAuth2Exception
     */
    public void addScope(Scope scope, int tenantID) throws IdentityOAuth2Exception {

        Connection conn = null;
        PreparedStatement ps = null;

        try {
            conn = IdentityDatabaseUtil.getDBConnection();
            conn.setAutoCommit(false);

            String scopeIdField = "SCOPE_ID";
            if (conn.getMetaData().getDriverName().contains("PostgreSQL")) {
                scopeIdField = "scope_id";
            }

            if (scope != null) {
                ps = conn.prepareStatement(SQLQueries.ADD_SCOPE, new String[]{scopeIdField});
                ps.setString(1, scope.getId());
                ps.setString(2, scope.getName());
                ps.setString(3, scope.getDescription());
                ps.setInt(4, tenantID);
                ps.execute();

                for (String binding : scope.getBindings()) {
                    if (StringUtils.isNotBlank(binding)) {
                        ps = conn.prepareStatement(SQLQueries.ADD_SCOPE_BINDING, new String[]{scopeIdField});
                        ps.setString(1, scope.getId());
                        ps.setString(2, binding);
                        ps.addBatch();
                    }
                    ps.executeBatch();
                }
                conn.commit();
            }
        } catch (SQLException e) {
            try {
                if (conn != null) {
                    conn.rollback();
                }
            } catch (SQLException e1) {
                String msg1 = "Error occurred while Rolling back changes done on Scopes Creation";
                log.error(msg1, e1);
                throw new IdentityOAuth2Exception(msg1, e1);
            }
            String msg = "Error occurred while creating scopes ";
            log.error(msg, e);
            throw new IdentityOAuth2Exception(msg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(conn, null, ps);
        }
    }

    /**
     * Get all available scopes
     *
     * @param tenantID tenant ID
     * @return available scope list
     * @throws IdentityOAuth2Exception
     */
    public Set<Scope> getAllScopes(int tenantID) throws IdentityOAuth2Exception {

        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        Set<Scope> scopes = new HashSet<>();
        Map<String, List<String>> scopeBindings = new HashMap<>();

        try {
            conn = IdentityDatabaseUtil.getDBConnection();
            conn.setAutoCommit(false);

            ps = conn.prepareStatement(SQLQueries.RETRIEVE_ALL_SCOPE_BINDINGS);
            ps.setInt(1, tenantID);
            rs = ps.executeQuery();
            while (rs.next()) {
                if (scopeBindings.containsKey(rs.getString(1)) && scopeBindings.get(rs.getString(1)) != null) {
                    scopeBindings.get(rs.getString(1)).add(rs.getString(2));
                } else {
                    scopeBindings.put(rs.getString(1), new ArrayList<String>());
                    scopeBindings.get(rs.getString(1)).add(rs.getString(2));
                }
            }

            ps = conn.prepareStatement(SQLQueries.RETRIEVE_ALL_SCOPES);
            ps.setInt(1, tenantID);
            rs = ps.executeQuery();

            while (rs.next()) {
                Scope scope = new Scope(rs.getString(1), rs.getString(2), rs.getString(3),
                        scopeBindings.get(rs.getString(1)));
                scopes.add(scope);
            }
            return scopes;
        } catch (SQLException e) {
            try {
                if (conn != null) {
                    conn.rollback();
                }
            } catch (SQLException e1) {
                String msg1 = "Error occurred while Rolling back changes done on Get all Scopes";
                log.error(msg1, e1);
                throw new IdentityOAuth2Exception(msg1, e1);
            }
            String msg = "Error occurred while getting all scopes ";
            log.error(msg, e);
            throw new IdentityOAuth2Exception(msg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(conn, null, ps);
        }
    }

    /**
     * Get Scopes with pagination
     *
     * @param offset   start index of the result set
     * @param limit    number of elements of the result set
     * @param tenantID tenant ID
     * @return available scope list
     * @throws IdentityOAuth2Exception
     */
    public Set<Scope> getScopesWithPagination(Integer offset, Integer limit, int tenantID) throws IdentityOAuth2Exception {

        Connection conn = null;
        NamedPreparedStatement namedPreparedStatement = null;
        PreparedStatement preparedStatement = null;
        ResultSet rs = null;
        Set<Scope> scopes = new HashSet<>();

        try {
            conn = IdentityDatabaseUtil.getDBConnection();
            conn.setAutoCommit(false);

            String query;
            if (conn.getMetaData().getDriverName().contains("MySQL")
                    || conn.getMetaData().getDriverName().contains("H2")) {
                query = SQLQueries.RETRIEVE_SCOPES_WITH_PAGINATION_MYSQL;
            } else if (conn.getMetaData().getDatabaseProductName().contains("DB2")) {
                query = SQLQueries.RETRIEVE_SCOPES_WITH_PAGINATION_DB2SQL;
            } else if (conn.getMetaData().getDriverName().contains("MS SQL")) {
                query = SQLQueries.RETRIEVE_SCOPES_WITH_PAGINATION_MSSQL;
            } else if (conn.getMetaData().getDriverName().contains("Microsoft") || conn.getMetaData()
                    .getDriverName().contains("microsoft")) {
                query = SQLQueries.RETRIEVE_SCOPES_WITH_PAGINATION_MSSQL;
            } else if (conn.getMetaData().getDriverName().contains("PostgreSQL")) {
                query = SQLQueries.RETRIEVE_SCOPES_WITH_PAGINATION_POSTGRESQL;
            } else if (conn.getMetaData().getDriverName().contains("Informix")) {
                // Driver name = "IBM Informix JDBC Driver for IBM Informix Dynamic Server"
                query = SQLQueries.RETRIEVE_SCOPES_WITH_PAGINATION_INFORMIX;
            } else {
                query = SQLQueries.RETRIEVE_SCOPES_WITH_PAGINATION_ORACLE;
            }
            namedPreparedStatement = new NamedPreparedStatement(conn, query);
            namedPreparedStatement.setInt(Oauth2ScopeConstants.SQLPlaceholders.TENANT_ID, tenantID);
            namedPreparedStatement.setInt(Oauth2ScopeConstants.SQLPlaceholders.OFFSET, offset);
            namedPreparedStatement.setInt(Oauth2ScopeConstants.SQLPlaceholders.LIMIT, limit);
            preparedStatement = namedPreparedStatement.getPreparedStatement();
            rs = preparedStatement.executeQuery();

            while (rs.next()) {
                Scope scope = new Scope(rs.getString(1), rs.getString(2), rs.getString(3), null);
                scopes.add(scope);
            }

            for (Scope scope : scopes) {
                List<String> bindings = new ArrayList<>();
                preparedStatement = conn.prepareStatement(SQLQueries.RETRIEVE_SCOPE_BINDINGS);
                preparedStatement.setString(1, scope.getId());
                rs = preparedStatement.executeQuery();
                while (rs.next()) {
                    bindings.add(rs.getString(1));
                }
                scope.setBindings(bindings);
            }
            return scopes;
        } catch (SQLException e) {
            try {
                if (conn != null) {
                    conn.rollback();
                }
            } catch (SQLException e1) {
                String msg1 = "Error occurred while Rolling back changes done on Get all Scopes with pagination";
                log.error(msg1, e1);
                throw new IdentityOAuth2Exception(msg1, e1);
            }
            String msg = "Error occurred while getting all scopes with pagination ";
            log.error(msg, e);
            throw new IdentityOAuth2Exception(msg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(conn, null, preparedStatement);
        }
    }

    /**
     * Get Scopes with pagination and filter
     *
     * @param attributeName  filter attribute
     * @param attributeValue filter attribute value
     * @param offset         start index of the result set
     * @param limit          number of elements of the result set
     * @param tenantID       tenant ID
     * @return available scope list
     * @throws IdentityOAuth2Exception
     */
    public Set<Scope> getScopesWithPaginationAndFilter(String attributeName, String attributeValue, Integer offset, Integer limit, int tenantID)
            throws IdentityOAuth2Exception {

        Connection conn = null;
        NamedPreparedStatement namedPreparedStatement = null;
        PreparedStatement preparedStatement = null;
        ResultSet rs = null;
        Set<Scope> scopes = new HashSet<>();

        try {
            conn = IdentityDatabaseUtil.getDBConnection();
            conn.setAutoCommit(false);

            String query;
            if (conn.getMetaData().getDriverName().contains("MySQL")
                    || conn.getMetaData().getDriverName().contains("H2")) {
                query = SQLQueries.RETRIEVE_SCOPES_WITH_PAGINATION_AND_FILTER_MYSQL;
            } else if (conn.getMetaData().getDatabaseProductName().contains("DB2")) {
                query = SQLQueries.RETRIEVE_SCOPES_WITH_PAGINATION_AND_FILTER_DB2SQL;
            } else if (conn.getMetaData().getDriverName().contains("MS SQL")) {
                query = SQLQueries.RETRIEVE_SCOPES_WITH_PAGINATION_AND_FILTER_MSSQL;
            } else if (conn.getMetaData().getDriverName().contains("Microsoft") || conn.getMetaData()
                    .getDriverName().contains("microsoft")) {
                query = SQLQueries.RETRIEVE_SCOPES_WITH_PAGINATION_AND_FILTER_MSSQL;
            } else if (conn.getMetaData().getDriverName().contains("PostgreSQL")) {
                query = SQLQueries.RETRIEVE_SCOPES_WITH_PAGINATION_AND_FILTER_POSTGRESQL;
            } else if (conn.getMetaData().getDriverName().contains("Informix")) {
                // Driver name = "IBM Informix JDBC Driver for IBM Informix Dynamic Server"
                query = SQLQueries.RETRIEVE_SCOPES_WITH_PAGINATION_AND_FILTER_INFORMIX;
            } else {
                query = SQLQueries.RETRIEVE_SCOPES_WITH_PAGINATION_AND_FILTER_ORACLE;
            }

            query = query.replace(Oauth2ScopeConstants.SQLPlaceholders.ATTRIBUTE_NAME, attributeName);
            namedPreparedStatement = new NamedPreparedStatement(conn, query);
            namedPreparedStatement.setInt(Oauth2ScopeConstants.SQLPlaceholders.TENANT_ID, tenantID);
            namedPreparedStatement.setString(Oauth2ScopeConstants.SQLPlaceholders.ATTRIBUTE_VALUE, attributeValue);
            namedPreparedStatement.setInt(Oauth2ScopeConstants.SQLPlaceholders.OFFSET, offset);
            namedPreparedStatement.setInt(Oauth2ScopeConstants.SQLPlaceholders.LIMIT, limit);
            preparedStatement = namedPreparedStatement.getPreparedStatement();
            rs = preparedStatement.executeQuery();

            while (rs.next()) {
                Scope scope = new Scope(rs.getString(1), rs.getString(2), rs.getString(3), null);
                scopes.add(scope);
            }

            for (Scope scope : scopes) {
                List<String> bindings = new ArrayList<>();
                preparedStatement = conn.prepareStatement(SQLQueries.RETRIEVE_SCOPE_BINDINGS);
                preparedStatement.setString(1, scope.getId());
                rs = preparedStatement.executeQuery();
                while (rs.next()) {
                    bindings.add(rs.getString(1));
                }
                scope.setBindings(bindings);
            }
            return scopes;
        } catch (SQLException e) {
            try {
                if (conn != null) {
                    conn.rollback();
                }
            } catch (SQLException e1) {
                String msg1 = "Error occurred while Rolling back changes done on Get all Scopes with Pagination and Filter";
                log.error(msg1, e1);
                throw new IdentityOAuth2Exception(msg1, e1);
            }
            String msg = "Error occurred while getting all scopes with pagination and filter";
            log.error(msg, e);
            throw new IdentityOAuth2Exception(msg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(conn, null, preparedStatement);
        }
    }

    /**
     * Get a scope by ID
     *
     * @param scopeID  scope ID of the scope
     * @param tenantID tenant ID
     * @return Scope for the provided ID
     * @throws IdentityOAuth2Exception
     */
    public Scope getScopeByID(String scopeID, int tenantID) throws IdentityOAuth2Exception {

        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        Scope scope = null;

        try {
            conn = IdentityDatabaseUtil.getDBConnection();
            conn.setAutoCommit(false);

            ps = conn.prepareStatement(SQLQueries.RETRIEVE_SCOPE_BY_ID);
            ps.setString(1, scopeID);
            ps.setInt(2, tenantID);
            rs = ps.executeQuery();

            String scopeName = null;
            String description = null;
            List<String> bindings = new ArrayList<>();

            while (rs.next()) {
                if (StringUtils.isBlank(scopeName)) {
                    scopeName = rs.getString(2);
                }
                if (StringUtils.isBlank(description)) {
                    description = rs.getString(3);
                }
                bindings.add(rs.getString(4));
            }
            if (StringUtils.isNotBlank(scopeName) && StringUtils.isNotBlank(description)) {
                scope = new Scope(scopeID, scopeName, description, bindings);
            }
            return scope;
        } catch (SQLException e) {
            try {
                if (conn != null) {
                    conn.rollback();
                }
            } catch (SQLException e1) {
                String msg1 = "Error occurred while Rolling back changes done on Get Scope by ID";
                log.error(msg1, e1);
                throw new IdentityOAuth2Exception(msg1, e1);
            }
            String msg = "Error occurred while getting scope by ID ";
            log.error(msg, e);
            throw new IdentityOAuth2Exception(msg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(conn, null, ps);
        }
    }

    /**
     * Get scope ID for the provided scope name
     *
     * @param scopeName name of the scope
     * @param tenantID  tenant ID
     * @return scope ID for the provided scope name
     * @throws IdentityOAuth2Exception
     */
    public String getScopeIDByName(String scopeName, int tenantID) throws IdentityOAuth2Exception {

        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        String scopeID = null;

        try {
            conn = IdentityDatabaseUtil.getDBConnection();
            conn.setAutoCommit(false);

            ps = conn.prepareStatement(SQLQueries.RETRIEVE_SCOPE_ID_BY_NAME);
            ps.setString(1, scopeName);
            ps.setInt(2, tenantID);
            rs = ps.executeQuery();

            if (rs.next()) {
                scopeID = rs.getString(1);
            }
            return scopeID;
        } catch (SQLException e) {
            try {
                if (conn != null) {
                    conn.rollback();
                }
            } catch (SQLException e1) {
                String msg1 = "Error occurred while Rolling back changes done on Get Scope ID by name";
                log.error(msg1, e1);
                throw new IdentityOAuth2Exception(msg1, e1);
            }
            String msg = "Error occurred while getting scope ID by name ";
            log.error(msg, e);
            throw new IdentityOAuth2Exception(msg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(conn, null, ps);
        }
    }

    /**
     * Delete a scope of the provided scope ID
     *
     * @param scopeID  scope ID
     * @param tenantID tenant ID
     * @throws IdentityOAuth2Exception
     */
    public void deleteScopeByID(String scopeID, int tenantID) throws IdentityOAuth2Exception {

        Connection conn = null;
        PreparedStatement ps = null;

        try {
            conn = IdentityDatabaseUtil.getDBConnection();
            conn.setAutoCommit(false);
            ps = conn.prepareStatement(SQLQueries.DELETE_SCOPE_BY_ID);
            ps.setString(1, scopeID);
            ps.setInt(2, tenantID);
            ps.execute();
            conn.commit();
        } catch (SQLException e) {
            try {
                if (conn != null) {
                    conn.rollback();
                }
            } catch (SQLException e1) {
                String msg1 = "Error occurred while Rolling back changes done on Scopes Deletion";
                log.error(msg1, e1);
                throw new IdentityOAuth2Exception(msg1, e1);
            }
            String msg = "Error occurred while deleting scopes ";
            log.error(msg, e);
            throw new IdentityOAuth2Exception(msg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(conn, null, ps);
        }
    }

    /**
     * Update a scope of the provided scope ID
     *
     * @param updatedScope details of the updated scope
     * @param tenantID     tenant ID
     * @throws IdentityOAuth2Exception
     */
    public void updateScopeByID(Scope updatedScope, int tenantID) throws IdentityOAuth2Exception {

        Connection conn = null;
        PreparedStatement ps = null;

        try {
            conn = IdentityDatabaseUtil.getDBConnection();
            conn.setAutoCommit(false);

            String scopeIdField = "SCOPE_ID";
            if (conn.getMetaData().getDriverName().contains("PostgreSQL")) {
                scopeIdField = "scope_id";
            }

            ps = conn.prepareStatement(SQLQueries.DELETE_SCOPE_BY_ID, new String[]{scopeIdField});
            ps.setString(1, updatedScope.getId());
            ps.setInt(2, tenantID);
            ps.execute();

            ps = conn.prepareStatement(SQLQueries.ADD_SCOPE, new String[]{scopeIdField});
            ps.setString(1, updatedScope.getId());
            ps.setString(2, updatedScope.getName());
            ps.setString(3, updatedScope.getDescription());
            ps.setInt(4, tenantID);
            ps.execute();

            for (String binding : updatedScope.getBindings()) {
                if (StringUtils.isNotBlank(binding)) {
                    ps = conn.prepareStatement(SQLQueries.ADD_SCOPE_BINDING, new String[]{scopeIdField});
                    ps.setString(1, updatedScope.getId());
                    ps.setString(2, binding);
                    ps.addBatch();
                }
                ps.executeBatch();
            }

            conn.commit();
        } catch (SQLException e) {
            try {
                if (conn != null) {
                    conn.rollback();
                }
            } catch (SQLException e1) {
                String msg1 = "Error occurred while Rolling back changes done on Scope Updating by Scope ID";
                log.error(msg1, e1);
                throw new IdentityOAuth2Exception(msg1, e1);
            }
            String msg = "Error occurred while updating scope by ID ";
            log.error(msg, e);
            throw new IdentityOAuth2Exception(msg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(conn, null, ps);
        }
    }
}
