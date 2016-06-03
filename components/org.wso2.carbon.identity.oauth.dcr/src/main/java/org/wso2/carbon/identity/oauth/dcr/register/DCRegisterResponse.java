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

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.oauth.dcr.model.OAuthApplication;


public class DCRegisterResponse extends IdentityResponse {

    private OAuthApplication oAuthApplication = null ;

    protected DCRegisterResponse(
            DCRRegisterResponseBuilder builder) {
        super(builder);
        this.oAuthApplication = builder.oAuthApplication ;
    }

    public OAuthApplication getoAuthApplication() {
        return oAuthApplication;
    }

    public static class DCRRegisterResponseBuilder extends  IdentityResponseBuilder{
        private OAuthApplication oAuthApplication = null ;

        public DCRRegisterResponseBuilder() {
            super();
        }

        public DCRRegisterResponseBuilder(
                IdentityMessageContext context) {
            super(context);
        }

        public DCRRegisterResponseBuilder setOAuthApplication(OAuthApplication oAuthApplication){
            this.oAuthApplication = oAuthApplication ;
            return this ;
        }

        @Override
        public DCRegisterResponse build() {
            return new DCRegisterResponse(this);
        }
    }
}
