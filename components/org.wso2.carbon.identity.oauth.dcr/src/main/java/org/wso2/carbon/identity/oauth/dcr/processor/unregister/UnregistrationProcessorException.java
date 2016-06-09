package org.wso2.carbon.identity.oauth.dcr.processor.unregister;

import org.wso2.carbon.identity.oauth.dcr.DCRManagementException;

public class UnregistrationProcessorException extends DCRManagementException {
    public UnregistrationProcessorException(String msg, Exception nestedEx) {
        super(msg, nestedEx);
    }

    public UnregistrationProcessorException(String message, Throwable cause) {
        super(message, cause);
    }

    public UnregistrationProcessorException(String msg) {
        super(msg);
    }

    public UnregistrationProcessorException(String message, String errorMessage) {
        super(message, errorMessage);
    }

    public UnregistrationProcessorException(String message, Throwable cause, String errorMessage) {
        super(message, cause, errorMessage);
    }
}
