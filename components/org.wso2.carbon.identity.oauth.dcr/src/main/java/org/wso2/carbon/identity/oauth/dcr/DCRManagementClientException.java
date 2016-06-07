package org.wso2.carbon.identity.oauth.dcr;


import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;

public class DCRManagementClientException extends FrameworkClientException {
    protected DCRManagementClientException(String errorDescription) {
        super(errorDescription);
    }

    public DCRManagementClientException(String errorDescription, Throwable cause) {
        super(errorDescription, cause);
    }
}
