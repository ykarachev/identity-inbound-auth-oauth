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

package org.wso2.carbon.identity.oauth.dcr.processor.register.model;

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;


public class RegistrationResponse extends IdentityResponse {


    private String clientId;
    private String clientName;
    private String callBackURL;
    private String clientSecret;

    protected RegistrationResponse(
            DCRRegisterResponseBuilder builder) {
        super(builder);
        this.clientId = builder.clientId ;
        this.clientName = builder.clientName ;
        this.callBackURL = builder.callBackURL ;
        this.clientSecret = builder.clientSecret ;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientName() {
        return clientName;
    }

    public String getCallBackURL() {
        return callBackURL;
    }

    public String getClientSecret() {
        return clientSecret;
    }



    public static class DCRRegisterResponseBuilder extends  IdentityResponseBuilder{

        private String clientId;
        private String clientName;
        private String callBackURL;
        private String clientSecret;

        public DCRRegisterResponseBuilder() {
            super();
        }

        public DCRRegisterResponseBuilder(
                IdentityMessageContext context) {
            super(context);
        }

        public DCRRegisterResponseBuilder setClientId(String clientId){
            this.clientId = clientId ;
            return this ;
        }

        public DCRRegisterResponseBuilder setClientName(String clientName){
            this.clientName = clientName ;
            return this ;
        }

        public DCRRegisterResponseBuilder setCallBackURL(String callBackURL){
            this.callBackURL = callBackURL ;
            return this ;
        }

        public DCRRegisterResponseBuilder setClientSecret(String clientSecret){
            this.clientSecret = clientSecret ;
            return this ;
        }

        @Override
        public RegistrationResponse build() {
            return new RegistrationResponse(this);
        }
    }

    public static class DCRegisterResponseConstants extends IdentityResponseConstants{
        public static final String OAUTH_CLIENT_ID = "client_id";
        public static final String OAUTH_CLIENT_SECRET = "client_secret";
        public static final String OAUTH_CLIENT_NAME = "client_name";
        public static final String OAUTH_CALLBACK_URIS = "callback_url";
    }
}
