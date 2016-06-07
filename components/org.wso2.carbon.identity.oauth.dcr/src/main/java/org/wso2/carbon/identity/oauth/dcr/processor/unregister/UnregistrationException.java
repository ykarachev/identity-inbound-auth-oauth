package org.wso2.carbon.identity.oauth.dcr.processor.unregister;

import org.wso2.carbon.identity.oauth.dcr.DCRManagementException;

public class UnregistrationException extends DCRManagementException {
    public UnregistrationException(String msg, Exception nestedEx) {
        super(msg, nestedEx);
    }

    public UnregistrationException(String message, Throwable cause) {
        super(message, cause);
    }

    public UnregistrationException(String msg) {
        super(msg);
    }

    public UnregistrationException(String message, String errorMessage) {
        super(message, errorMessage);
    }

    public UnregistrationException(String message, Throwable cause, String errorMessage) {
        super(message, cause, errorMessage);
    }
}
