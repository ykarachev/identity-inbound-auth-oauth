package org.wso2.carbon.identity.oauth.dcr.unregister;

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;


public class DCUnregisterRequest extends IdentityRequest {

    private String consumerKey;
    private String applicationName;
    private String userId;

    public String getConsumerKey() {
        return consumerKey;
    }

    public String getApplicationName() {
        return applicationName;
    }

    public String getUserId() {
        return userId;
    }

    protected DCUnregisterRequest(DCRUnregisterRequestBuilder builder) {
        super(builder);
        this.consumerKey = builder.consumerKey;
        this.applicationName = builder.applicationName;
        this.userId = builder.userId;
    }

    public static class DCRUnregisterRequestBuilder extends IdentityRequestBuilder{
        private String consumerKey;
        private String applicationName;
        private String userId;

        public void setConsumerKey(String consumerKey) {
            this.consumerKey = consumerKey;
        }

        public void setApplicationName(String applicationName) {
            this.applicationName = applicationName;
        }

        public void setUserId(String userId) {
            this.userId = userId;
        }

        public DCUnregisterRequest build() {
            return new DCUnregisterRequest(this);
        }
    }
}
