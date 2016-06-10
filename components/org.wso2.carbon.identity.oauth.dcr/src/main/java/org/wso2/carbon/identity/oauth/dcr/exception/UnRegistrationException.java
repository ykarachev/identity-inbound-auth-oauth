package org.wso2.carbon.identity.oauth.dcr.exception;


import org.wso2.carbon.identity.oauth.dcr.DCRException;

public class UnRegistrationException extends DCRException{
    public UnRegistrationException(String msg, Exception nestedEx) {
        super(msg, nestedEx);
    }

    public UnRegistrationException(String message, Throwable cause) {
        super(message, cause);
    }

    public UnRegistrationException(String msg) {
        super(msg);
    }

    public UnRegistrationException(String message, String errorMessage) {
        super(message, errorMessage);
    }

    public UnRegistrationException(String message, Throwable cause, String errorMessage) {
        super(message, cause, errorMessage);
    }
}
