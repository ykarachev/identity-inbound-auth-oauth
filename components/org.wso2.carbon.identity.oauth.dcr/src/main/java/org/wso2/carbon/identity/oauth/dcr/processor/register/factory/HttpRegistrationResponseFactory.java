package org.wso2.carbon.identity.oauth.dcr.processor.register.factory;


import org.json.simple.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dcr.processor.register.RegistrationProcessorException;
import org.wso2.carbon.identity.oauth.dcr.processor.register.model.RegistrationResponse;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;

public class HttpRegistrationResponseFactory extends HttpIdentityResponseFactory {
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
        httpIdentityResponseBuilder.setBody(generateSuccessfulResponse(registrationResponse));
        httpIdentityResponseBuilder.setStatusCode(HttpServletResponse.SC_CREATED);
        httpIdentityResponseBuilder.addHeader(OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL,
                                              OAuthConstants.HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE);
        httpIdentityResponseBuilder.addHeader(OAuthConstants.HTTP_RESP_HEADER_PRAGMA,
                                              OAuthConstants.HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE);
        httpIdentityResponseBuilder.addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON);
    }

    public HttpIdentityResponse.HttpIdentityResponseBuilder handleException(FrameworkException exception) {

        HttpIdentityResponse.HttpIdentityResponseBuilder builder = new HttpIdentityResponse.HttpIdentityResponseBuilder();
        builder.setStatusCode(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        builder.addHeader(OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL,
                          OAuthConstants.HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE);
        builder.addHeader(OAuthConstants.HTTP_RESP_HEADER_PRAGMA,
                          OAuthConstants.HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE);
        return builder;
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
        return 100;
    }

    public boolean canHandle(FrameworkException exception) {
        if(exception instanceof RegistrationProcessorException){
            return true ;
        }
        return false;
    }


    private String generateSuccessfulResponse(RegistrationResponse registrationResponse) {
        JSONObject obj = new JSONObject();
        obj.put(RegistrationResponse.DCRegisterResponseConstants.OAUTH_CLIENT_ID, registrationResponse.getClientId());
        obj.put(RegistrationResponse.DCRegisterResponseConstants.OAUTH_CLIENT_NAME, registrationResponse.getClientName());
        obj.put(RegistrationResponse.DCRegisterResponseConstants.OAUTH_CALLBACK_URIS, registrationResponse.getCallBackURL());
        obj.put(RegistrationResponse.DCRegisterResponseConstants.OAUTH_CLIENT_SECRET, registrationResponse
                .getClientSecret());
        return obj.toString();
    }


}
