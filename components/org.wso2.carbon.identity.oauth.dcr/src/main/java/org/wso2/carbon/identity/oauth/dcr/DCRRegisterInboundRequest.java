package org.wso2.carbon.identity.oauth.dcr;

import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkRuntimeException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundRequest;

/**
 * Created by yasiru on 4/20/16.
 */
public class DCRRegisterInboundRequest extends InboundRequest {
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

    public DCRRegisterInboundRequest(DCRRegisterInboundRequestBuilder builder) {
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

    public static class DCRRegisterInboundRequestBuilder extends InboundRequestBuilder {
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
        public DCRRegisterInboundRequest build() throws FrameworkRuntimeException {
            return new DCRRegisterInboundRequest(this);
        }
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

}
