/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.expmapper;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.endpoint.exception.AccessDeniedException;
import org.wso2.carbon.identity.oauth.endpoint.exception.BadRequestException;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidApplicationClientException;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestException;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestParentException;
import org.wso2.carbon.identity.oauth.endpoint.exception.TokenEndpointAccessDeniedException;
import org.wso2.carbon.identity.oauth.endpoint.exception.TokenEndpointBadRequestException;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;


import java.net.URI;
import java.net.URISyntaxException;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

public class InvalidRequestExceptionMapper implements ExceptionMapper<InvalidRequestParentException> {

    private final Log log = LogFactory.getLog(InvalidRequestExceptionMapper.class);

    @Override
    public Response toResponse(InvalidRequestParentException exception) {

        if (exception instanceof InvalidRequestException) {
            try {
                return Response.status(HttpServletResponse.SC_FOUND).location(new URI(EndpointUtil.getErrorPageURL
                        (OAuth2ErrorCodes.INVALID_REQUEST, exception.getMessage(), null))).build();
            } catch (URISyntaxException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while getting endpoint error page URL", e);
                }
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
            }
        } else if (exception instanceof AccessDeniedException) {
            try {
                return Response.status(HttpServletResponse.SC_FOUND).location(new URI(EndpointUtil.getErrorPageURL
                        (OAuth2ErrorCodes.ACCESS_DENIED, exception.getMessage(), null))).build();
            } catch (URISyntaxException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while getting endpoint error page URL", e);
                }
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
            }
        } else if (exception instanceof InvalidApplicationClientException) {
            try {
                OAuthResponse oAuthResponse = OAuthASResponse.errorResponse(HttpServletResponse.SC_UNAUTHORIZED)
                        .setError(OAuth2ErrorCodes.INVALID_CLIENT)
                        .setErrorDescription(exception.getMessage()).buildJSONMessage();

                return Response.status(oAuthResponse.getResponseStatus()).entity(oAuthResponse.getBody()).build();
            } catch (OAuthSystemException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while getting endpoint error page URL", e);
                }
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
            }
        }  else if (exception instanceof BadRequestException) {
            try {
                return Response.status(HttpServletResponse.SC_BAD_REQUEST).location(new URI(EndpointUtil.getErrorPageURL(
                        OAuth2ErrorCodes.INVALID_REQUEST, exception.getMessage(), null))).build();
            } catch (URISyntaxException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while getting endpoint error page URL", e);
                }
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
            }
        } else if (exception instanceof TokenEndpointBadRequestException) {
            try {
                if (exception.getMessage() != null) {
                    OAuthResponse oAuthResponse = OAuthASResponse.errorResponse(HttpServletResponse.SC_BAD_REQUEST)
                            .setError(OAuth2ErrorCodes.INVALID_REQUEST).setErrorDescription(exception.getMessage())
                            .buildJSONMessage();
                    return Response.status(oAuthResponse.getResponseStatus()).entity(oAuthResponse.getBody()).build();

                }

                OAuthResponse res = OAuthASResponse
                        .errorResponse(HttpServletResponse.SC_BAD_REQUEST).error((OAuthProblemException) exception.getCause())
                        .buildJSONMessage();
                return Response.status(res.getResponseStatus()).entity(res.getBody()).build();


            } catch (OAuthSystemException e) {
                if (log.isDebugEnabled()) {
                    log.debug("OAuth System error while token invoking token endpoint", e);
                }
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
            }

        } else if (exception instanceof TokenEndpointAccessDeniedException) {
            try {
                OAuthResponse response = OAuthASResponse.errorResponse(HttpServletResponse.SC_UNAUTHORIZED)
                        .setError(OAuth2ErrorCodes.INVALID_CLIENT)
                        .setErrorDescription(exception.getMessage()).buildJSONMessage();
                return Response.status(response.getResponseStatus())
                        .header(OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE, EndpointUtil.getRealmInfo())
                        .entity(response.getBody()).build();
            } catch (OAuthSystemException e) {
                if (log.isDebugEnabled()) {
                    log.debug("OAuth System error while token invoking token endpoint", e);
                }
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
            }
        } else {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }
    }
}
