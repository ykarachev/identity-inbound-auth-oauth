package org.wso2.carbon.identity.oauth.dcr.register;


import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;

import javax.servlet.http.HttpServletResponse;

public class DCRegisterHttpResponseFactory extends HttpIdentityResponseFactory {
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
        DCRegisterResponse dcRegisterResponse = (DCRegisterResponse)identityResponse ;
        httpIdentityResponseBuilder.setBody(dcRegisterResponse.getoAuthApplication().toString());
        httpIdentityResponseBuilder.setStatusCode(HttpServletResponse.SC_CREATED);
        httpIdentityResponseBuilder.addHeader(OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL,
                                              OAuthConstants.HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE);
        httpIdentityResponseBuilder.addHeader(OAuthConstants.HTTP_RESP_HEADER_PRAGMA,
                                              OAuthConstants.HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE);
        httpIdentityResponseBuilder.addHeader("Content-Type", "application/json");
    }

    @Override
    public boolean canHandle(IdentityResponse identityResponse) {
        if(identityResponse instanceof DCRegisterResponse) {
            return true;
        }
        return false;
    }
}
