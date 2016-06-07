package org.wso2.carbon.identity.oauth.dcr.processor.register;


import org.wso2.carbon.identity.oauth.dcr.DCRManagementException;

public class RegistrationProcessorException extends DCRManagementException {
    public RegistrationProcessorException(String msg, Exception nestedEx) {
        super(msg, nestedEx);
    }

    public RegistrationProcessorException(String message, Throwable cause) {
        super(message, cause);
    }

    public RegistrationProcessorException(String msg) {
        super(msg);
    }

    public RegistrationProcessorException(String message, String errorMessage) {
        super(message, errorMessage);
    }

    public RegistrationProcessorException(String message, Throwable cause, String errorMessage) {
        super(message, cause, errorMessage);
    }
}
