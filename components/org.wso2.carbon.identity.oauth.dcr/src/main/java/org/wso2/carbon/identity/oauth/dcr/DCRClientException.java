package org.wso2.carbon.identity.oauth.dcr;


import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;

public class DCRClientException extends FrameworkClientException {
    protected DCRClientException(String errorDescription) {
        super(errorDescription);
    }

    public DCRClientException(String errorDescription, Throwable cause) {
        super(errorDescription, cause);
    }
}
