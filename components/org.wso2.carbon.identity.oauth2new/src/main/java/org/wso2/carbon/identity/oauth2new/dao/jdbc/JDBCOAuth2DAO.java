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

package org.wso2.carbon.identity.oauth2new.dao.jdbc;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2new.OAuth2;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2TokenMessageContext;
import org.wso2.carbon.identity.oauth2new.dao.OAuth2DAO;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2RuntimeException;
import org.wso2.carbon.identity.oauth2new.handler.HandlerManager;
import org.wso2.carbon.identity.oauth2new.handler.persist.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.oauth2new.model.AuthzCode;
import org.wso2.carbon.identity.oauth2new.revoke.RevocationMessageContext;
import org.wso2.carbon.identity.oauth2new.util.OAuth2Util;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.HashSet;
import java.util.Set;
import java.util.TimeZone;
import java.util.UUID;

public class JDBCOAuth2DAO extends OAuth2DAO {

    private static final Log log = LogFactory.getLog(JDBCOAuth2DAO.class);

    @Override
    public AccessToken getLatestActiveOrExpiredAccessToken(String consumerKey, AuthenticatedUser authzUser, Set<String> scopes, OAuth2MessageContext messageContext) {
        return null;
    }

    @Override
    public void storeAccessToken(AccessToken newAccessToken, String oldAccessToken,
                                 String authzCode, OAuth2MessageContext messageContext) {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        String accessTokenId = UUID.randomUUID().toString();
        try {
            if (oldAccessToken != null) {
                updateAccessTokenState(connection, oldAccessToken, OAuth2.TokenState.EXPIRED, messageContext);
            }
            if (authzCode != null) {
                updateAuthzCodeState(connection, authzCode, OAuth2.TokenState.INACTIVE, messageContext);
            }
            storeAccessToken(connection, accessTokenId, newAccessToken, messageContext);
            updateAccessTokenForAuthzCode(connection, authzCode, accessTokenId, messageContext);
            connection.commit();
        } catch (SQLException e) {
            throw OAuth2RuntimeException.error("Error occurred while storing access token", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, null);
        }
    }

    protected void storeAccessToken(Connection connection, String accessTokenId, AccessToken newAccessToken,
                                    OAuth2MessageContext messageContext) {

        String sql = SQLQueries.INSERT_OAUTH2_ACCESS_TOKEN;
        String sqlAddScopes = SQLQueries.INSERT_OAUTH2_TOKEN_SCOPE;
        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(messageContext);
        PreparedStatement prepStmt = null;
        try {
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, processor.getProcessedAccessToken(newAccessToken.getAccessToken()));
            prepStmt.setString(2, processor.getProcessedRefreshToken(newAccessToken.getRefreshToken()));
            prepStmt.setString(3, newAccessToken.getAuthzUser().getUserName());
            int tenantId = IdentityTenantUtil.getTenantId(newAccessToken.getAuthzUser().getTenantDomain());
            prepStmt.setInt(4, tenantId);
            prepStmt.setString(5, newAccessToken.getAuthzUser().getUserStoreDomain());
            prepStmt.setTimestamp(6, newAccessToken.getAccessTokenIssuedTime(), Calendar.getInstance(TimeZone.getTimeZone("UTC")));
            prepStmt.setTimestamp(7, newAccessToken.getRefreshTokenIssuedTime(), Calendar.getInstance(TimeZone
                    .getTimeZone("UTC")));
            prepStmt.setLong(8, newAccessToken.getAccessTokenValidity());
            prepStmt.setLong(9, newAccessToken.getRefreshTokenValidity());
            prepStmt.setString(10, OAuth2Util.hashScopes(newAccessToken.getScopes()));
            prepStmt.setString(11, newAccessToken.getAccessTokenState());
            prepStmt.setString(13, accessTokenId);
            prepStmt.setString(14, newAccessToken.getGrantType());
            prepStmt.setString(15, newAccessToken.getAuthzUser().getAuthenticatedSubjectIdentifier());
            prepStmt.setString(16, processor.getProcessedClientId(newAccessToken.getClientId()));
            prepStmt.execute();

            prepStmt = connection.prepareStatement(sqlAddScopes);

            if (CollectionUtils.isNotEmpty(newAccessToken.getScopes())) {
                for (String scope : newAccessToken.getScopes()) {
                    prepStmt.setString(1, accessTokenId);
                    prepStmt.setString(2, scope);
                    prepStmt.setInt(3, tenantId);
                    prepStmt.execute();
                }
            }

        } catch (SQLException e) {
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(null, null, prepStmt);
        }
    }

    @Override
    public String getAccessTokenByAuthzCode(String authorizationCode, OAuth2MessageContext messageContext) {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        String sqlQuery = SQLQueries.GET_ACCESS_TOKEN_BY_CODE;
        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(messageContext);
        PreparedStatement ps = null;
        String accessToken = null;
        try {
            if(connection.getMetaData().getDriverName().contains("MySQL")){
                sqlQuery = SQLQueries.GET_ACCESS_TOKEN_BY_CODE_MYSQL ;
            }
            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, processor.getProcessedAuthzCode(authorizationCode));
            ResultSet resultSet = ps.executeQuery();
            while(resultSet.next()){
                accessToken = resultSet.getString(1);
            }
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
        return accessToken;
    }

    @Override
    public void updateAccessTokenState(String accessToken, String tokenState, OAuth2TokenMessageContext messageContext) {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        String sqlQuery = SQLQueries.UPDATE_ACCESS_TOKEN_STATE_BY_CODE;
        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(messageContext);
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, tokenState);
            ps.setString(2, UUID.randomUUID().toString());
            ps.setString(3, processor.getProcessedAccessToken(accessToken));
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
    }

    protected void updateAccessTokenState(Connection connection, String accessToken, String tokenState,
                                          OAuth2MessageContext messageContext) {

        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(messageContext);
        PreparedStatement prepStmt = null;
        try {
            String sql = SQLQueries.UPDATE_ACCESS_TOKEN_STATE;
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, tokenState);
            prepStmt.setString(2, UUID.randomUUID().toString());
            prepStmt.setString(3, processor.getProcessedAccessToken(accessToken));
            prepStmt.executeUpdate();
        } catch (SQLException e) {
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        } finally {
            IdentityDatabaseUtil.closeStatement(prepStmt);
        }
    }

    @Override
    public AccessToken getLatestAccessTokenByRefreshToken(String refreshToken, OAuth2MessageContext messageContext) {

        AccessToken accessToken = null;
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        String sql = null;
        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(messageContext);
        try {
            String mySqlQuery = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_MYSQL;
            String db2Query = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_DB2SQL;
            String oracleQuery = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_ORACLE;
            String msSqlQuery = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_MSSQL;
            String informixQuery = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_INFORMIX;
            String postgreSqlQuery = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_POSTGRESQL;

            if (connection.getMetaData().getDriverName().contains("MySQL")
                    || connection.getMetaData().getDriverName().contains("H2")) {
                sql = mySqlQuery;
            } else if(connection.getMetaData().getDatabaseProductName().contains("DB2")){
                sql = db2Query;
            } else if (connection.getMetaData().getDriverName().contains("MS SQL")) {
                sql = msSqlQuery;
            } else if (connection.getMetaData().getDriverName().contains("Microsoft")) {
                sql = msSqlQuery;
            } else if (connection.getMetaData().getDriverName().contains("PostgreSQL")) {
                sql = postgreSqlQuery;
            } else if (connection.getMetaData().getDriverName().contains("INFORMIX")) {
                sql = informixQuery;
            } else {
                sql = oracleQuery;
            }

            if (refreshToken == null) {
                sql = sql.replace("REFRESH_TOKEN = ?", "REFRESH_TOKEN IS NULL");
            }

            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, processor.getProcessedRefreshToken(refreshToken));
            resultSet = prepStmt.executeQuery();
            int iterateId = 0;
            String bearerToken = null;
            String userName = null;
            int tenantId;
            String userDomain = null;
            Set<String> scopeSet = new HashSet<>();
            String accessTokenState = null;
            Timestamp accessTokenIssuedTime = null;
            long accessTokenValidity = -1l;
            Timestamp refreshTokenIssuedTime = null;
            long refreshTokenValidity = -1l;
            String grantType = null;
            String subjectIdentifier = null;
            String clientId = null;
            AuthenticatedUser user = new AuthenticatedUser();
            while (resultSet.next()) {
                if (iterateId == 0) {
                    bearerToken = processor.getPreprocessedAccessToken(
                            resultSet.getString(1));
                    userName = resultSet.getString(2);
                    tenantId = resultSet.getInt(3);
                    userDomain = resultSet.getString(4);
                    scopeSet = OAuth2Util.buildScopeSet(resultSet.getString(5));
                    accessTokenState = resultSet.getString(6);
                    accessTokenIssuedTime = resultSet.getTimestamp(7,
                            Calendar.getInstance(TimeZone.getTimeZone("UTC")));
                    accessTokenValidity = resultSet.getLong(8);
                    refreshTokenIssuedTime = resultSet.getTimestamp(9);
                    refreshTokenValidity = resultSet.getLong(10);
                    grantType = resultSet.getString(11);
                    subjectIdentifier = resultSet.getString(12);
                    clientId = resultSet.getString(13);
                    user.setUserName(userName);
                    user.setUserStoreDomain(userDomain);
                    user.setTenantDomain(IdentityTenantUtil.getTenantDomain(tenantId));
                    user.setAuthenticatedSubjectIdentifier(subjectIdentifier);
                } else {
                    scopeSet.add(resultSet.getString(5));
                }
                iterateId++;
            }
            if(bearerToken != null){
                accessToken = new AccessToken(bearerToken, clientId, subjectIdentifier, grantType,
                        accessTokenState, accessTokenIssuedTime, accessTokenValidity);
                if(!scopeSet.isEmpty()) {
                    accessToken.setScopes(scopeSet);
                }
                accessToken.setRefreshToken(refreshToken);
                accessToken.setRefreshTokenIssuedTime(refreshTokenIssuedTime);
                accessToken.setRefreshTokenValidity(refreshTokenValidity);
            }
            connection.commit();
        } catch (SQLException e) {
            throw OAuth2RuntimeException.error("Error when validating a refresh token", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }

        return accessToken;
    }

    @Override
    public void storeAuthzCode(AuthzCode authzCode, OAuth2MessageContext messageContext) {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(messageContext);
        try {
            prepStmt = connection.prepareStatement(SQLQueries.STORE_AUTHORIZATION_CODE);
            prepStmt.setString(1, UUID.randomUUID().toString());
            prepStmt.setString(2, processor.getProcessedAuthzCode(authzCode.getAuthzCode()));
            prepStmt.setString(3, authzCode.getRedirectURI());
            prepStmt.setString(4, OAuth2Util.buildScopeString(authzCode.getScopes()));
            prepStmt.setString(5, authzCode.getAuthzUser().getUserName());
            prepStmt.setString(6, authzCode.getAuthzUser().getUserStoreDomain());
            int tenantId = IdentityTenantUtil.getTenantId(authzCode.getAuthzUser().getTenantDomain());
            prepStmt.setInt(7, tenantId);
            prepStmt.setTimestamp(8, authzCode.getIssuedTime(),
                    Calendar.getInstance(TimeZone.getTimeZone("UTC")));
            prepStmt.setLong(9, authzCode.getValidityPeriod());
            prepStmt.setString(10, authzCode.getAuthzUser().getAuthenticatedSubjectIdentifier());
            prepStmt.setString(11, processor.getPreprocessedClientId(authzCode.getClientId()));
            prepStmt.execute();
            connection.commit();
        } catch (SQLException e) {
            throw OAuth2RuntimeException.error("Error when storing the authorization code for consumer key : " +
                    authzCode.getClientId(), e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    @Override
    public AuthzCode getAuthzCode(String authzCode, OAuth2MessageContext messageContext) {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(messageContext);
        AuthzCode authorizationCode = null;
        try {
            prepStmt = connection.prepareStatement(SQLQueries.RETRIEVE_AUTHZ_CODE);
            prepStmt.setString(1, processor.getProcessedAuthzCode(authzCode));
            resultSet = prepStmt.executeQuery();
            if (resultSet.next()) {
                String authorizedUser = resultSet.getString(1);
                String userStoreDomain = resultSet.getString(2);
                int tenantId = resultSet.getInt(3);
                String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
                String scopeString = resultSet.getString(4);
                String callbackUrl = resultSet.getString(5);
                Timestamp issuedTime = resultSet.getTimestamp(6, Calendar.getInstance(TimeZone.getTimeZone("UTC")));
                long validityPeriod = resultSet.getLong(7);
                String codeState = resultSet.getString(8);
                String subjectIdentifier = resultSet.getString(9);
                String clientId = resultSet.getString(10);
                AuthenticatedUser user = new AuthenticatedUser();
                user.setUserName(authorizedUser);
                user.setTenantDomain(tenantDomain);
                user.setUserStoreDomain(userStoreDomain);
                user.setAuthenticatedSubjectIdentifier(subjectIdentifier);
                authorizationCode =  new AuthzCode(authzCode, clientId, callbackUrl, user,
                        issuedTime, validityPeriod, codeState);
                authorizationCode.setScopes(OAuth2Util.buildScopeSet(scopeString));
            }
            connection.commit();
        } catch (SQLException e) {
            throw OAuth2RuntimeException.error("Error when validating an authorization code", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
        return authorizationCode;
    }

    @Override
    public void updateAuthzCodeState(String authzCode, String state, OAuth2MessageContext messageContext) {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(messageContext);
        PreparedStatement prepStmt = null;
        try {
            prepStmt = connection.prepareStatement(SQLQueries.UPDATE_AUTHZ_CODE_STATE);
            prepStmt.setString(1, state);
            prepStmt.setString(2, processor.getProcessedAuthzCode(authzCode));
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    public void updateAuthzCodeState(Connection connection, String authzCode,
                                     String state, OAuth2MessageContext messageContext) {

        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(messageContext);
        PreparedStatement prepStmt = null;
        try {
            prepStmt = connection.prepareStatement(SQLQueries.UPDATE_AUTHZ_CODE_STATE);
            prepStmt.setString(1, state);
            prepStmt.setString(2, processor.getProcessedAuthzCode(authzCode));
            prepStmt.executeUpdate();
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        } finally {
            IdentityDatabaseUtil.closeStatement(prepStmt);
        }
    }

    protected void updateAccessTokenForAuthzCode(Connection connection, String authzCode,
                                                 String newAccessTokenId, OAuth2MessageContext messageContext) {

        PreparedStatement prepStmt = null;
        try {
            String sql;
            if (connection.getMetaData().getDriverName().contains("MySQL")){
                sql = SQLQueries.UPDATE_NEW_TOKEN_AGAINST_AUTHZ_CODE_MYSQL;
            } else{
                sql = SQLQueries.UPDATE_NEW_TOKEN_AGAINST_AUTHZ_CODE;
            }
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, newAccessTokenId);
            prepStmt.setString(2, authzCode);
            prepStmt.executeUpdate();
        } catch (SQLException e) {
            throw OAuth2RuntimeException.error("Error while updating Access Token against authorization code for " +
                    "access token with ID : " + newAccessTokenId, e);
        } finally {
            IdentityDatabaseUtil.closeStatement(prepStmt);
        }
    }

    public Set<String> getAuthorizedClientIDs(AuthenticatedUser authzUser, RevocationMessageContext messageContext) {

        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(messageContext);
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;
        ResultSet rs = null;
        Set<String> distinctConsumerKeys = new HashSet<>();
        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authzUser.toString());
        String tenantDomain = authzUser.getTenantDomain();
        String tenantAwareUsernameWithNoUserDomain = authzUser.getUserName();
        String userDomain = authzUser.getUserStoreDomain();
        if ((userDomain != null)){
            userDomain.toUpperCase();
        }
        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            String sqlQuery = SQLQueries.GET_DISTINCT_APPS_AUTHORIZED_BY_USER_ALL_TIME;
            if (!isUsernameCaseSensitive){
                sqlQuery = sqlQuery.replace("AUTHZ_USER", "LOWER(AUTHZ_USER)");
            }
            ps = connection.prepareStatement(sqlQuery);
            if (isUsernameCaseSensitive) {
                ps.setString(1, tenantAwareUsernameWithNoUserDomain);
            } else {
                ps.setString(1, tenantAwareUsernameWithNoUserDomain.toLowerCase());
            }
            ps.setInt(2, tenantId);
            ps.setString(3, userDomain);
            rs = ps.executeQuery();
            while (rs.next()) {
                String consumerKey = processor.getPreprocessedClientId(rs.getString(1));
                distinctConsumerKeys.add(consumerKey);
            }
        } catch (SQLException e) {
            throw OAuth2RuntimeException.error("Error occurred while retrieving all distinct Client IDs " +
                    "authorized by User ID : " + authzUser + " until now", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rs, ps);
        }
        return distinctConsumerKeys;
    }

    public AccessToken getAccessToken(String bearerToken, OAuth2MessageContext messageContext) {

        AccessToken accessToken = null;
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        String sql = SQLQueries.RETRIEVE_ACTIVE_EXPIRED_ACCESS_TOKEN;
        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(messageContext);
        try {
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, processor.getProcessedAccessToken(bearerToken));
            resultSet = prepStmt.executeQuery();
            int iterateId = 0;
            Set<String> scopes = new HashSet<>();
            while (resultSet.next()) {
                if (iterateId == 0) {
                    String clientId = processor.getPreprocessedClientId(resultSet.getString(1));
                    String authorizedUser = resultSet.getString(2);
                    int tenantId = resultSet.getInt(3);
                    String userDomain = resultSet.getString(4);
                    scopes = OAuth2Util.buildScopeSet(resultSet.getString(5));
                    Timestamp accessTokenIssuedTime = resultSet.getTimestamp(6,
                            Calendar.getInstance(TimeZone.getTimeZone
                                    ("UTC")));
                    Timestamp refreshTokenIssuedTime = resultSet.getTimestamp(7,
                            Calendar.getInstance(TimeZone.getTimeZone("UTC")));
                    long accessTokenValidity = resultSet.getLong(8);
                    long refreshTokenValidity = resultSet.getLong(9);
                    String refreshToken = resultSet.getString(10);
                    String grantType = resultSet.getString(12);
                    String subjectIdentifier = resultSet.getString(13);
                    String tokenState = resultSet.getString(14);

                    AuthenticatedUser user = new AuthenticatedUser();
                    user.setUserName(authorizedUser);
                    user.setUserStoreDomain(userDomain);
                    user.setTenantDomain(IdentityTenantUtil.getTenantDomain(tenantId));
                    user.setAuthenticatedSubjectIdentifier(subjectIdentifier);

                    accessToken = new AccessToken(bearerToken, clientId, subjectIdentifier, grantType, tokenState,
                            accessTokenIssuedTime, accessTokenValidity);
                    accessToken.setRefreshToken(refreshToken);
                    accessToken.setRefreshTokenIssuedTime(refreshTokenIssuedTime);
                    accessToken.setRefreshTokenValidity(refreshTokenValidity);
                } else {
                    scopes.add(resultSet.getString(5));
                }
                iterateId++;
            }
            connection.commit();
        } catch (SQLException e) {
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
        return accessToken;
    }

    public void revokeAccessToken(String accessToken, RevocationMessageContext messageContext) {

        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(messageContext);
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        String sqlQuery = org.wso2.carbon.identity.oauth2new.dao.jdbc.SQLQueries.UPDATE_ACCESS_TOKEN_STATE;
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, OAuth2.TokenState.REVOKED);
            ps.setString(2, UUID.randomUUID().toString());
            ps.setString(3, processor.getProcessedAccessToken(accessToken));
            ps.execute();
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        }  finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
    }

    public void revokeRefreshToken(String refreshToken, RevocationMessageContext messageContext) {

        TokenPersistenceProcessor processor = HandlerManager.getInstance().getTokenPersistenceProcessor(messageContext);
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        String sqlQuery = SQLQueries.REVOKE_REFRESH_TOKEN;
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, UUID.randomUUID().toString());
            ps.setString(2, processor.getProcessedRefreshToken(refreshToken));
            ps.execute();
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        }  finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
    }
}
