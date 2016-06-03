package org.wso2.carbon.identity.oauth.dcr.unregister;

import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;

import javax.servlet.http.HttpServletResponse;


public class DCUnregisterHttpResponseFactory extends HttpIdentityResponseFactory {
    @Override
    public String getName() {
        return null;
    }


    @Override
    public boolean canHandle(IdentityResponse identityResponse) {
        if(identityResponse instanceof DCUnregisterResponse) {
            return true;
        }
        return false;
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
        httpIdentityResponseBuilder.setStatusCode(HttpServletResponse.SC_NO_CONTENT);
        httpIdentityResponseBuilder.addHeader(OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL,
                                              OAuthConstants.HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE);
        httpIdentityResponseBuilder.addHeader(OAuthConstants.HTTP_RESP_HEADER_PRAGMA,
                                              OAuthConstants.HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE);
    }
}
