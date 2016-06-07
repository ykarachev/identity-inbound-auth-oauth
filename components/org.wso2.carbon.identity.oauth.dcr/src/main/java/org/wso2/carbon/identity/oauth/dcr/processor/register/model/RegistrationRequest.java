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

import java.util.ArrayList;
import java.util.List;

/**
 * DCR Request data for Register a oauth application
 *
 */
public class RegistrationRequest extends IdentityRequest {


    private List<String> redirectUris = new ArrayList<>();
    private String grantType;

    private String applicationType;
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
    private String tokenScope;

    private String audience;

    public RegistrationRequest(DCRRegisterInboundRequestBuilder builder) {

        super(builder);
        this.redirectUris = builder.redirectUris;
        this.grantType = builder.grantType;

        this.applicationType = builder.applicationType;
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
        this.tokenScope = builder.tokenScope;

        this.audience = builder.audience;
    }

    public List<String> getRedirectUris() {
        return redirectUris;
    }

    public String getGrantType() {
        return grantType;
    }

    public String getApplicationType() {
        return applicationType;
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

    public String getTokenScope() {
        return tokenScope;
    }

    public String getAudience() {
        return audience;
    }

    public static class DCRRegisterInboundRequestBuilder extends IdentityRequestBuilder {

        private List<String> redirectUris = new ArrayList<>();
        private String grantType;

        private String applicationType;

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
        private String tokenScope;

        private String audience;

        public DCRRegisterInboundRequestBuilder setApplicationType(String applicationType) {
            this.applicationType = applicationType;
            return this;
        }

        public DCRRegisterInboundRequestBuilder setRedirectUris(List<String> redirectUris) {
            this.redirectUris = redirectUris;
            return this;
        }

        public List<String> getRedirectUris() {
            return redirectUris;
        }

        public DCRRegisterInboundRequestBuilder setClientName(String clientName) {
            this.clientName = clientName;
            return this;
        }

        public DCRRegisterInboundRequestBuilder setLogoUri(String logoUri) {
            this.logoUri = logoUri;
            return this;
        }

        public DCRRegisterInboundRequestBuilder setSubjectType(String subjectType) {
            this.subjectType = subjectType;
            return this;
        }

        public DCRRegisterInboundRequestBuilder setSectorIdentifierUri(String sectorIdentifierUri) {
            this.sectorIdentifierUri = sectorIdentifierUri;
            return this;
        }

        public DCRRegisterInboundRequestBuilder setTokenEndpointAuthMethod(String tokenEndpointAuthMethod) {
            this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
            return this;
        }

        public DCRRegisterInboundRequestBuilder setJwksUri(String jwksUri) {
            this.jwksUri = jwksUri;
            return this;
        }

        public DCRRegisterInboundRequestBuilder setUserInfoEncryptedResponseAlg(String userInfoEncryptedResponseAlg) {
            this.userInfoEncryptedResponseAlg = userInfoEncryptedResponseAlg;
            return this;
        }

        public DCRRegisterInboundRequestBuilder setUserInfoEncryptedResponseEnc(String userInfoEncryptedResponseEnc) {
            this.userInfoEncryptedResponseEnc = userInfoEncryptedResponseEnc;
            return this;
        }

        public DCRRegisterInboundRequestBuilder setContacts(String[] contacts) {
            this.contacts = contacts;
            return this;
        }

        public DCRRegisterInboundRequestBuilder setRequestUris(String[] requestUris) {
            this.requestUris = requestUris;
            return this;
        }

        public DCRRegisterInboundRequestBuilder setOwner(String owner) {
            this.owner = owner;
            return this;
        }

        public DCRRegisterInboundRequestBuilder setTokenScope(String tokenScope) {
            this.tokenScope = tokenScope;
            return this;
        }

        public DCRRegisterInboundRequestBuilder setGrantType(String grantType) {
            this.grantType = grantType;
            return this;
        }

        public DCRRegisterInboundRequestBuilder setAudience(String audience) {
            this.audience = audience;
            return this;
        }

        @Override
        public RegistrationRequest build() throws FrameworkRuntimeException {
            return new RegistrationRequest(this);
        }
    }

    public static class RegisterRequestConstant extends IdentityRequestConstants {

        public final static String GRANT_TYPE = "grant_types" ;
        public final static String REDIRECT_URIS = "redirect_uris" ;

        public final static String CLIENT_NAME = "clientName" ;
        public final static String TOKEN_SCOPE = "tokenScope" ;
        public final static String OWNER = "owner" ;

    }

}
