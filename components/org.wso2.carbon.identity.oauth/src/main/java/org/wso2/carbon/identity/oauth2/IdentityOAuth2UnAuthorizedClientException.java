package org.wso2.carbon.identity.oauth2;

/**
 * temporally exception type added to handle unauthorized client exception
 */
public class IdentityOAuth2UnAuthorizedClientException extends IdentityOAuth2Exception {

    public IdentityOAuth2UnAuthorizedClientException(String message) {
        super(message);
    }

    public IdentityOAuth2UnAuthorizedClientException(String message, Throwable e) {
        super(message, e);
    }
}
