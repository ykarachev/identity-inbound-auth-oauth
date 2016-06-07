package org.wso2.carbon.identity.oidc.dcr;


import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;

public class OIDCDCRManagementClientException extends FrameworkClientException {
    protected OIDCDCRManagementClientException(String errorDescription) {
        super(errorDescription);
    }

    public OIDCDCRManagementClientException(String errorDescription, Throwable cause) {
        super(errorDescription, cause);
    }
}
