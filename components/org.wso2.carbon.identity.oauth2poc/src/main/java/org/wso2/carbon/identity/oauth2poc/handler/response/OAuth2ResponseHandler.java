package org.wso2.carbon.identity.oauth2poc.handler.response;

import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.processor.handler.response.AbstractResponseHandler;
import org.wso2.carbon.identity.application.authentication.framework.processor.request.AuthenticationRequest;
import org.wso2.carbon.identity.oauth2poc.bean.message.request.authz.OAuth2AuthzRequest;
import org.wso2.carbon.identity.oauth2poc.exception.OAuth2RuntimeException;


public abstract class OAuth2ResponseHandler extends AbstractResponseHandler {

    /**
     * Tells if refresh token must be issued or not for this access token request.
     *
     * @param messageContext The runtime message context
     * @return {@code true} if refresh tokens must be issued
     */
    public boolean issueRefreshToken(AuthenticationContext messageContext) {

        AuthenticationRequest request = messageContext.getInitialAuthenticationRequest();
        if(request instanceof OAuth2AuthzRequest){
            return issueRefreshToken((OAuth2AuthzRequest)request, messageContext);
        } else {
            throw OAuth2RuntimeException.error("Invalid OAuth2AuthzRequest - unknown sub type");
        }
    }

    /**
     * Tells if refresh token must be issued or not for this access token request to the authorization endpoint.
     *
     * @param messageContext The runtime authorization message context
     * @return {@code true} if refresh tokens must be issued
     */
    protected boolean issueRefreshToken(OAuth2AuthzRequest request, AuthenticationContext messageContext) {
        return false;
    }
}
