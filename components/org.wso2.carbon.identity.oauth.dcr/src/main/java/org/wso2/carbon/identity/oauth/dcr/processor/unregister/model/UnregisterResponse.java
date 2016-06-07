package org.wso2.carbon.identity.oauth.dcr.processor.unregister.model;

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;

public class UnregisterResponse extends IdentityResponse {

    private boolean isUnregistered = false ;

    protected UnregisterResponse(
            DCUnregisterResponseBuilder builder) {
        super(builder);
        this.isUnregistered = builder.isUnregistered ;
    }

    public boolean isUnregistered() {
        return isUnregistered;
    }

    public static class DCUnregisterResponseBuilder extends  IdentityResponseBuilder{

        private boolean isUnregistered = false ;

        public DCUnregisterResponseBuilder() {
            super();
        }

        public DCUnregisterResponseBuilder(
                IdentityMessageContext context) {
            super(context);
        }

        public DCUnregisterResponseBuilder setIsUnregistered(boolean isUnregistered) {
            this.isUnregistered = isUnregistered;
            return this ;
        }

        @Override
        public UnregisterResponse build() {
            return new UnregisterResponse(this);
        }
    }
}
