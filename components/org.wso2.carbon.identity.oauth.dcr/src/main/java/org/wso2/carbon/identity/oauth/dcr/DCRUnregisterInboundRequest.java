package org.wso2.carbon.identity.oauth.dcr;

import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundRequest;

/**
 * Created by yasiru on 4/25/16.
 */
public class DCRUnregisterInboundRequest extends InboundRequest {
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

    protected DCRUnregisterInboundRequest(DCRInboundUnregisterInboundRequestBuilder builder) {
        super(builder);
        this.consumerKey = builder.consumerKey;
        this.applicationName = builder.applicationName;
        this.userId = builder.userId;
    }

    public static class DCRInboundUnregisterInboundRequestBuilder extends InboundRequestBuilder{
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

        public DCRUnregisterInboundRequest build() {
            return new DCRUnregisterInboundRequest(this);
        }
    }

}
