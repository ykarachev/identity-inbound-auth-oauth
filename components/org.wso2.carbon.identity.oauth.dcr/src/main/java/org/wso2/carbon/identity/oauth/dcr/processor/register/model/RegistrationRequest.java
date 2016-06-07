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

import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkRuntimeException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;

/**
 * DCR Request data for Register a oauth application
 *
 */
public class RegistrationRequest extends IdentityRequest {

    private String applicationType;
    private String[] redirectUris;
    private String clientName;
    private String logoUri;
    private String subjectType;
    private String sectorIdentifierUri;
    private String tokenEndpointAuthMethod;
    private String jwksUri;
    private String userInfoEncryptedResponseAlg;
    private String userInfoEncryptedResponseEnc;
    private String[] contacts;
    private String[] requestUris;
    private String owner;
    private String callbackUrl;
    private String tokenScope;
    private String grantType;
    private boolean saasApp;
    private String audience;

    public RegistrationRequest(DCRRegisterInboundRequestBuilder builder) {

        super(builder);
        this.applicationType = builder.applicationType;
        this.redirectUris = builder.redirectUris;
        this.clientName = builder.clientName;
        this.logoUri = builder.logoUri;
        this.subjectType = builder.subjectType;
        this.sectorIdentifierUri = builder.sectorIdentifierUri;
        this.tokenEndpointAuthMethod = builder.tokenEndpointAuthMethod;
        this.jwksUri = builder.jwksUri;
        this.userInfoEncryptedResponseAlg = builder.userInfoEncryptedResponseAlg;
        this.userInfoEncryptedResponseEnc = builder.userInfoEncryptedResponseEnc;
        this.contacts = builder.contacts;
        this.requestUris = builder.requestUris;
        this.owner = builder.owner;
        this.callbackUrl = builder.callbackUrl;
        this.tokenScope = builder.tokenScope;
        this.grantType = builder.grantType;
        this.saasApp = builder.saasApp;
        this.audience = builder.audience;
    }


    public String getApplicationType() {
        return applicationType;
    }

    public String[] getRedirectUris() {
        return redirectUris;
    }

    public String getClientName() {
        return clientName;
    }

    public String getLogoUri() {
        return logoUri;
    }

    public String getSubjectType() {
        return subjectType;
    }

    public String getSectorIdentifierUri() {
        return sectorIdentifierUri;
    }

    public String getTokenEndpointAuthMethod() {
        return tokenEndpointAuthMethod;
    }

    public String getJwksUri() {
        return jwksUri;
    }

    public String getUserInfoEncryptedResponseAlg() {
        return userInfoEncryptedResponseAlg;
    }

    public String getUserInfoEncryptedResponseEnc() {
        return userInfoEncryptedResponseEnc;
    }

    public String[] getContacts() {
        return contacts;
    }

    public String[] getRequestUris() {
        return requestUris;
    }

    public String getOwner() {
        return owner;
    }

    public String getCallbackUrl() {
        return callbackUrl;
    }

    public String getTokenScope() {
        return tokenScope;
    }

    public String getGrantType() {
        return grantType;
    }

    public boolean isSaasApp() {
        return saasApp;
    }

    public String getAudience() {
        return audience;
    }



    public static class DCRRegisterInboundRequestBuilder extends IdentityRequestBuilder {

        private String applicationType;
        private String[] redirectUris;
        private String clientName;
        private String logoUri;
        private String subjectType;
        private String sectorIdentifierUri;
        private String tokenEndpointAuthMethod;
        private String jwksUri;
        private String userInfoEncryptedResponseAlg;
        private String userInfoEncryptedResponseEnc;
        private String[] contacts;
        private String[] requestUris;
        private String owner;
        private String callbackUrl;
        private String tokenScope;
        private String grantType;
        private boolean saasApp;
        private String audience;

        public void setApplicationType(String applicationType) {
            this.applicationType = applicationType;
        }

        public void setRedirectUris(String[] redirectUris) {
            this.redirectUris = redirectUris;
        }

        public void setClientName(String clientName) {
            this.clientName = clientName;
        }

        public void setLogoUri(String logoUri) {
            this.logoUri = logoUri;
        }

        public void setSubjectType(String subjectType) {
            this.subjectType = subjectType;
        }

        public void setSectorIdentifierUri(String sectorIdentifierUri) {
            this.sectorIdentifierUri = sectorIdentifierUri;
        }

        public void setTokenEndpointAuthMethod(String tokenEndpointAuthMethod) {
            this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
        }

        public void setJwksUri(String jwksUri) {
            this.jwksUri = jwksUri;
        }

        public void setUserInfoEncryptedResponseAlg(String userInfoEncryptedResponseAlg) {
            this.userInfoEncryptedResponseAlg = userInfoEncryptedResponseAlg;
        }

        public void setUserInfoEncryptedResponseEnc(String userInfoEncryptedResponseEnc) {
            this.userInfoEncryptedResponseEnc = userInfoEncryptedResponseEnc;
        }

        public void setContacts(String[] contacts) {
            this.contacts = contacts;
        }

        public void setRequestUris(String[] requestUris) {
            this.requestUris = requestUris;
        }

        public void setOwner(String owner) {
            this.owner = owner;
        }

        public void setCallbackUrl(String callbackUrl) {
            this.callbackUrl = callbackUrl;
        }

        public void setTokenScope(String tokenScope) {
            this.tokenScope = tokenScope;
        }

        public void setGrantType(String grantType) {
            this.grantType = grantType;
        }

        public void setSaasApp(boolean saasApp) {
            this.saasApp = saasApp;
        }

        public void setAudience(String audience) {
            this.audience = audience;
        }

        @Override
        public RegistrationRequest build() throws FrameworkRuntimeException {
            return new RegistrationRequest(this);
        }
    }

    public static class DCRRegisterInboundRequestConstant extends IdentityRequestConstants {
        public final static String CLIENT_NAME = "clientName" ;
        public final static String CALLBACK_URL = "callbackUrl" ;
        public final static String TOKEN_SCOPE = "tokenScope" ;
        public final static String OWNER = "owner" ;
        public final static String GRANT_TYPE = "grantType" ;
        public final static String SAAS_APP = "saasApp" ;
    }

}
