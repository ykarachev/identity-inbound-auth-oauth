package org.wso2.carbon.identity.oauth.dcr.processor.register.factory;


import org.json.simple.JSONArray;
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
        httpIdentityResponseBuilder.setBody(generateSuccessfulResponse(registrationResponse).toJSONString());
        httpIdentityResponseBuilder.setStatusCode(HttpServletResponse.SC_CREATED);
        httpIdentityResponseBuilder.addHeader(OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL,
                                              OAuthConstants.HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE);
        httpIdentityResponseBuilder.addHeader(OAuthConstants.HTTP_RESP_HEADER_PRAGMA,
                                              OAuthConstants.HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE);
        httpIdentityResponseBuilder.addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON);
    }

    public HttpIdentityResponse.HttpIdentityResponseBuilder handleException(FrameworkException exception) {
        HttpIdentityResponse.HttpIdentityResponseBuilder builder = new HttpIdentityResponse.HttpIdentityResponseBuilder();
        String errorMessage = generateErrorResponse("ddd", exception.getMessage()).toJSONString();
        builder.setBody(errorMessage);
        builder.setStatusCode(HttpServletResponse.SC_BAD_REQUEST);
        builder.addHeader(OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL,
                          OAuthConstants.HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE);
        builder.addHeader(OAuthConstants.HTTP_RESP_HEADER_PRAGMA,
                          OAuthConstants.HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE);
        builder.addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON);
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


    protected JSONObject generateSuccessfulResponse(RegistrationResponse registrationResponse) {
        JSONObject obj = new JSONObject();
        obj.put(RegistrationResponse.DCRegisterResponseConstants.CLIENT_ID, registrationResponse
                .getRegistrationResponseProfile().getClientId());
        obj.put(RegistrationResponse.DCRegisterResponseConstants.CLIENT_NAME, registrationResponse.getRegistrationResponseProfile()
                .getClientName());
        JSONArray jsonArray = new JSONArray();
        for (String redirectUri : registrationResponse.getRegistrationResponseProfile().getRedirectUrls()){
            jsonArray.add(redirectUri);
        }
        obj.put(RegistrationResponse.DCRegisterResponseConstants.REDIRECT_URIS, jsonArray);

        jsonArray = new JSONArray();
        for (String grantType : registrationResponse.getRegistrationResponseProfile().getGrantTypes()){
            jsonArray.add(grantType);
        }
        obj.put(RegistrationResponse.DCRegisterResponseConstants.GRANT_TYPES, jsonArray);

        obj.put(RegistrationResponse.DCRegisterResponseConstants.CLIENT_SECRET, registrationResponse.getRegistrationResponseProfile()
                .getClientSecret());
        return obj;
    }

    protected JSONObject generateErrorResponse(String error, String description){
        JSONObject obj = new JSONObject();
        obj.put("error", error);
        obj.put("error_description", description);
        return obj;
    }


}
