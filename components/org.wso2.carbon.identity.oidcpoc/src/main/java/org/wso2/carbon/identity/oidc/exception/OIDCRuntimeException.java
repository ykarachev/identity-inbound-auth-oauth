package org.wso2.carbon.identity.oidc.exception;

import org.wso2.carbon.identity.oauth2poc.exception.OAuth2RuntimeException;

public class OIDCRuntimeException extends OAuth2RuntimeException {

    protected OIDCRuntimeException(String errorDescription) {
        super(errorDescription);
    }

    protected OIDCRuntimeException(String errorDescription, Throwable cause) {
        super(errorDescription, cause);
    }

    public static OIDCRuntimeException error(String errorDescription){
        return new OIDCRuntimeException(errorDescription);
    }

    public static OIDCRuntimeException error(String errorDescription, Throwable cause){
        return new OIDCRuntimeException(errorDescription, cause);
    }
}
