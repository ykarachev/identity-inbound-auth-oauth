package org.wso2.carbon.identity.oidc.dcr.processor.register;


import org.wso2.carbon.identity.oidc.dcr.OIDCDCRManagementException;

public class OIDCRegistrationProcessorException extends OIDCDCRManagementException {
    public OIDCRegistrationProcessorException(String msg, Exception nestedEx) {
        super(msg, nestedEx);
    }

    public OIDCRegistrationProcessorException(String message, Throwable cause) {
        super(message, cause);
    }

    public OIDCRegistrationProcessorException(String msg) {
        super(msg);
    }

    public OIDCRegistrationProcessorException(String message, String errorMessage) {
        super(message, errorMessage);
    }

    public OIDCRegistrationProcessorException(String message, Throwable cause, String errorMessage) {
        super(message, cause, errorMessage);
    }
}
