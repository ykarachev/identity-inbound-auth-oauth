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

package org.wso2.carbon.identity.oauth.dcr.register;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkRuntimeException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.oauth.dcr.DCRClientException;
import org.wso2.carbon.identity.oauth.dcr.util.DCRConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.HttpHeaders;
import java.io.IOException;
import java.io.Reader;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;

/**
 * DCRegisterRequestFactory build the request for DCR Registry Request.
 */
public class DCRegisterRequestFactory extends HttpIdentityRequestFactory{

    private static Log log = LogFactory.getLog(DCRegisterRequestFactory.class);

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) throws
                                                                                       FrameworkRuntimeException {
        boolean canHandle = false ;
        if (request != null) {
            Matcher matcher = DCRConstants.DCR_ENDPOINT_REGISTER_URL_PATTERN.matcher(request.getRequestURI());
            if (matcher.matches() && HttpMethod.POST.equals(request.getMethod())) {
                canHandle =  true;
            }
        }
        if(log.isDebugEnabled()){
            log.debug("canExceptionHandle "+ canHandle +" by DCRegisterRequestFactory.");
        }
        return canHandle;
    }


    @Override
    public DCRegisterRequest.DCRRegisterInboundRequestBuilder create(HttpServletRequest request,
                                                                      HttpServletResponse response)
            throws FrameworkClientException {

        if(log.isDebugEnabled()){
            log.debug("create DCRegisterRequest.DCRRegisterInboundRequestBuilder by DCRegisterRequestFactory.");
        }
        DCRegisterRequest.DCRRegisterInboundRequestBuilder registerRequestBuilder = new
                DCRegisterRequest.DCRRegisterInboundRequestBuilder();
        create(registerRequestBuilder, request, response);

        return registerRequestBuilder;

    }

    @Override
    public void create(IdentityRequest.IdentityRequestBuilder builder, HttpServletRequest request,
                       HttpServletResponse response) throws FrameworkClientException {

        DCRegisterRequest.DCRRegisterInboundRequestBuilder registerRequestBuilder = (DCRegisterRequest.DCRRegisterInboundRequestBuilder)builder ;
        super.create(registerRequestBuilder, request, response);

        Map<String, String> headers = new HashMap<>();
        headers.put(HttpHeaders.AUTHORIZATION, request.getHeader(HttpHeaders.AUTHORIZATION));


        registerRequestBuilder.setHeaders(headers);
        registerRequestBuilder.setRequestURI(request.getRequestURI());
        registerRequestBuilder.setMethod(request.getMethod());
        try {
            Reader requestBodyReader = request.getReader();
            JSONParser jsonParser = new JSONParser();
            JSONObject jsonData = (JSONObject) jsonParser.parse(requestBodyReader);
            if(log.isDebugEnabled()){
                log.debug("DCR request json : " + jsonData.toJSONString());
            }

            registerRequestBuilder.setClientName((String) jsonData.get(DCRegisterRequest
                                                                               .DCRRegisterInboundRequestConstant
                                                                               .CLIENT_NAME));
            registerRequestBuilder.setCallbackUrl((String) jsonData.get(DCRegisterRequest
                                                                                .DCRRegisterInboundRequestConstant
                                                                                .CALLBACK_URL));
            registerRequestBuilder.setTokenScope((String) jsonData.get(DCRegisterRequest
                                                                               .DCRRegisterInboundRequestConstant
                                                                               .TOKEN_SCOPE));
            registerRequestBuilder.setOwner((String) jsonData.get(DCRegisterRequest
                                                                          .DCRRegisterInboundRequestConstant.OWNER));
            registerRequestBuilder.setGrantType((String) jsonData.get(DCRegisterRequest
                                                                              .DCRRegisterInboundRequestConstant
                                                                              .GRANT_TYPE));
            registerRequestBuilder.setSaasApp((Boolean) jsonData.get(DCRegisterRequest
                                                                             .DCRRegisterInboundRequestConstant.SAAS_APP));
        } catch (IOException e) {
            String errorMessage = "Error occurred while reading servlet request body, " + e.getMessage() ;
            throw new DCRClientException(errorMessage, e);
        } catch (ParseException e) {
            String errorMessage = "Error occurred while parsing the json object, " + e.getMessage() ;
            throw new DCRClientException(errorMessage, e);
        }
    }
}
