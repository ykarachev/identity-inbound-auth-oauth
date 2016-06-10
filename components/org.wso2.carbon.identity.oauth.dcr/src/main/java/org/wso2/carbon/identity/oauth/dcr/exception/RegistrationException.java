package org.wso2.carbon.identity.oauth.dcr.exception;


import org.wso2.carbon.identity.oauth.dcr.DCRException;

public class RegistrationException extends DCRException{
    public RegistrationException(String msg, Exception nestedEx) {
        super(msg, nestedEx);
    }

    public RegistrationException(String message, Throwable cause) {
        super(message, cause);
    }

    public RegistrationException(String msg) {
        super(msg);
    }

    public RegistrationException(String message, String errorMessage) {
        super(message, errorMessage);
    }

    public RegistrationException(String message, Throwable cause, String errorMessage) {
        super(message, cause, errorMessage);
    }
}
