package org.wso2.carbon.identity.oidc.dcr;


import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;

public class OIDCDCRClientException extends FrameworkClientException {
    protected OIDCDCRClientException(String errorDescription) {
        super(errorDescription);
    }

    public OIDCDCRClientException(String errorDescription, Throwable cause) {
        super(errorDescription, cause);
    }
}
