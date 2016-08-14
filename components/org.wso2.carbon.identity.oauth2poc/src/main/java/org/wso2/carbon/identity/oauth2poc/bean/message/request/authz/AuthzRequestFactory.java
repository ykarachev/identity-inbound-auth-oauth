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

package org.wso2.carbon.identity.oauth2poc.bean.message.request.authz;

import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.framework.FrameworkClientException;
import org.wso2.carbon.identity.oauth2poc.bean.message.request.OAuth2IdentityRequestFactory;
import org.wso2.carbon.identity.oauth2poc.exception.OAuth2ClientException;
import org.wso2.carbon.identity.oauth2poc.util.OAuth2Util;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AuthzRequestFactory<T extends OAuth2AuthzRequest.AuthzRequestBuilder> extends OAuth2IdentityRequestFactory<T> {

    @Override
    public String getName() {
        return "AuthzRequestFactory";
    }

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) {
        if(StringUtils.isNotBlank(request.getParameter(OAuth.OAUTH_RESPONSE_TYPE))) {
            return true;
        }
        return false;
    }
    @Override
    public OAuth2AuthzRequest.AuthzRequestBuilder create(HttpServletRequest request,
                                                         HttpServletResponse response) throws OAuth2ClientException {

        OAuth2AuthzRequest.AuthzRequestBuilder builder = new OAuth2AuthzRequest.AuthzRequestBuilder
                (request, response);
        try {
            create((T) builder, request, response);
        } catch (FrameworkClientException e) {
            throw OAuth2ClientException.error(e.getMessage(), e);
        }
        return builder;
    }

    @Override
    public void create(T builder,HttpServletRequest request,
                                                         HttpServletResponse response) throws OAuth2ClientException {

        try {
            super.create(builder, request, response);
        } catch (FrameworkClientException e) {
            throw OAuth2ClientException.error(e.getMessage(), e);
        }

        builder.setResponseType(request.getParameter(OAuth.OAUTH_RESPONSE_TYPE));
        builder.setClientId(request.getParameter(OAuth.OAUTH_CLIENT_ID));
        builder.setRedirectURI(request.getParameter(OAuth.OAUTH_REDIRECT_URI));
        builder.setState(request.getParameter(OAuth.OAUTH_STATE));
        builder.setScopes(OAuth2Util.buildScopeSet(request.getParameter(OAuth.OAUTH_SCOPE)));

    }
}
