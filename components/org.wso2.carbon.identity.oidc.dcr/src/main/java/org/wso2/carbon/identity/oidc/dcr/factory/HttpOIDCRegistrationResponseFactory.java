package org.wso2.carbon.identity.oidc.dcr.factory;


import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dcr.factory.HttpRegistrationResponseFactory;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationResponse;
import org.wso2.carbon.identity.oidc.dcr.processor.register.OIDCRegistrationProcessorException;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;

public class HttpOIDCRegistrationResponseFactory extends HttpRegistrationResponseFactory {
    @Override
    public String getName() {
        return null;
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder create(IdentityResponse identityResponse) {
        HttpIdentityResponse.HttpIdentityResponseBuilder httpIdentityResponseBuilder = new HttpIdentityResponse
                .HttpIdentityResponseBuilder();
        create(httpIdentityResponseBuilder, identityResponse);
        return httpIdentityResponseBuilder;
    }

    @Override
    public void create(HttpIdentityResponse.HttpIdentityResponseBuilder httpIdentityResponseBuilder, IdentityResponse identityResponse) {
        RegistrationResponse registrationResponse = (RegistrationResponse)identityResponse ;
        //super.create(httpIdentityResponseBuilder, identityResponse);
        httpIdentityResponseBuilder.setStatusCode(HttpServletResponse.SC_CREATED);
        httpIdentityResponseBuilder.addHeader(OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL,
                                              OAuthConstants.HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE);
        httpIdentityResponseBuilder.addHeader(OAuthConstants.HTTP_RESP_HEADER_PRAGMA,
                                              OAuthConstants.HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE);
        httpIdentityResponseBuilder.addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON);
        httpIdentityResponseBuilder.setBody(generateSuccessfulResponse(registrationResponse).toJSONString());
    }

    public HttpIdentityResponse.HttpIdentityResponseBuilder handleException(FrameworkException exception) {

        HttpIdentityResponse.HttpIdentityResponseBuilder builder = new HttpIdentityResponse.HttpIdentityResponseBuilder();
        builder.setStatusCode(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        return super.handleException(exception);
    }

    @Override
    public boolean canHandle(IdentityResponse identityResponse) {
        if(identityResponse instanceof RegistrationResponse) {
            return true;
        }
        return false;
    }

    @Override
    public int getPriority() {
        return 50;
    }

    public boolean canHandle(FrameworkException exception) {
        if(exception instanceof OIDCRegistrationProcessorException){
            return true ;
        }
        return false;
    }



}
