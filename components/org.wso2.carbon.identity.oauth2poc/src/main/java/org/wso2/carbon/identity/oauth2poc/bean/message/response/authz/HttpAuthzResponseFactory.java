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

package org.wso2.carbon.identity.oauth2poc.bean.message.response.authz;

import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.oauth2poc.OAuth2;
import org.wso2.carbon.identity.oauth2poc.exception.OAuth2RuntimeException;

public class HttpAuthzResponseFactory extends HttpIdentityResponseFactory {

    @Override
    public String getName() {
        return "HttpTokenResponseFactory";
    }

    @Override
    public boolean canHandle(IdentityResponse identityResponse) {
        if(identityResponse instanceof AuthzResponse) {
            return true;
        }
        return false;
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder create(IdentityResponse identityResponse) {

        AuthzResponse authzResponse = ((AuthzResponse)identityResponse);
        HttpIdentityResponse.HttpIdentityResponseBuilder builder = new HttpIdentityResponse.HttpIdentityResponseBuilder();
        OAuthResponse response = null;
        try {
            response = authzResponse.getBuilder().buildQueryMessage();
        } catch (OAuthSystemException e) {
            throw OAuth2RuntimeException.error("Error occurred while building query message for authorization " +
                                               "response");
        }
        builder.setStatusCode(response.getResponseStatus());
        builder.setHeaders(response.getHeaders());
        builder.addHeader(OAuth2.Header.CACHE_CONTROL,
                          OAuth2.HeaderValue.CACHE_CONTROL_NO_STORE);
        builder.addHeader(OAuth2.Header.PRAGMA,
                          OAuth2.HeaderValue.PRAGMA_NO_CACHE);
        return builder;
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder create(
            HttpIdentityResponse.HttpIdentityResponseBuilder builder, IdentityResponse identityResponse) {

        AuthzResponse authzResponse = ((AuthzResponse)identityResponse);
        OAuthResponse response = null;
        try {
            response = authzResponse.getBuilder().buildQueryMessage();
        } catch (OAuthSystemException e) {
            throw OAuth2RuntimeException.error("Error occurred while building query message for authorization " +
                                               "response");
        }
        builder.setStatusCode(response.getResponseStatus());
        builder.setHeaders(response.getHeaders());
        builder.addHeader(OAuth2.Header.CACHE_CONTROL,
                          OAuth2.HeaderValue.CACHE_CONTROL_NO_STORE);
        builder.addHeader(OAuth2.Header.PRAGMA,
                          OAuth2.HeaderValue.PRAGMA_NO_CACHE);
        return builder;
    }
}
