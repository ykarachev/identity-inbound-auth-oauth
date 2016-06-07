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

package org.wso2.carbon.identity.oidc.dcr.processor.register.model;

import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkRuntimeException;
import org.wso2.carbon.identity.oauth.dcr.processor.register.model.RegistrationRequest;

/**
 * DCR Request data for Register a oauth application
 *
 */
public class OIDCRegistrationRequest extends RegistrationRequest {


    public OIDCRegistrationRequest(OIDCRegisterRequestBuilder builder) {

        super(builder);
    }





    public static class OIDCRegisterRequestBuilder extends RegistrationRequest.DCRRegisterInboundRequestBuilder {


        @Override
        public OIDCRegistrationRequest build() throws FrameworkRuntimeException {
            return new OIDCRegistrationRequest(this);
        }
    }

    public static class OIDCRegisterRequestConstant extends DCRRegisterInboundRequestConstant {

    }

}
