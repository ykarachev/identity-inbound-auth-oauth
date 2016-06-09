package org.wso2.carbon.identity.oauth.dcr.processor.unregister.model;

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;

public class UnregistrationResponse extends IdentityResponse {

    private boolean isUnregistered = false ;

    protected UnregistrationResponse(
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
        public UnregistrationResponse build() {
            return new UnregistrationResponse(this);
        }
    }
}
