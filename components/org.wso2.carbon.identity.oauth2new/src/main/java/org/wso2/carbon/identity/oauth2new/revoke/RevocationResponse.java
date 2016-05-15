package org.wso2.carbon.identity.oauth2new.revoke;

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;

public class RevocationResponse extends IdentityResponse {

    private String callback;

    protected RevocationResponse(IdentityResponseBuilder builder) {
        super(builder);
        this.callback = ((RevocationResponseBuilder)builder).callback;
    }

    public String getCallback() {
        return this.callback;
    }

    public static class RevocationResponseBuilder extends IdentityResponseBuilder {

        private String callback;

        public RevocationResponseBuilder(IdentityMessageContext context) {
            super(context);
        }

        public RevocationResponseBuilder setCallback(String callback) {
            this.callback = callback;
            return this;
        }

        public RevocationResponse build() {
            return new RevocationResponse(this);
        }
    }
}
