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

package org.wso2.carbon.identity.oauth2new.introspect;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.oauth2new.bean.message.request.OAuth2IdentityRequestFactory;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2ClientException;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class IntrospectionRequestFactory extends OAuth2IdentityRequestFactory {

    @Override
    public String getName() {
        return "IntrospectionRequestFactory";
    }

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) {
        if(StringUtils.isNotBlank(request.getParameter("token"))) {
            return true;
        }
        return false;
    }

    @Override
    public IntrospectionRequest.IntrospectionRequestBuilder create(HttpServletRequest request,
                                                                   HttpServletResponse response) throws OAuth2ClientException{

        IntrospectionRequest.IntrospectionRequestBuilder builder = new IntrospectionRequest.IntrospectionRequestBuilder
                (request, response);
        builder.setTenantDomain(request.getParameter(MultitenantConstants.TENANT_DOMAIN));
        builder.setToken(request.getParameter("token"));
        builder.setTokenTypeHint(request.getParameter("token_type_hint"));
        return builder;
    }
}
