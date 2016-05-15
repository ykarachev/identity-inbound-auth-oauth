package org.wso2.carbon.identity.oidc.userinfo;

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;

public class UserInfoResponse extends IdentityResponse {

    protected UserInfoResponse(IdentityResponseBuilder builder) {
        super(builder);
    }

    public static class UserInfoResponseBuilder extends IdentityResponseBuilder {

        public UserInfoResponseBuilder(IdentityMessageContext context) {
            super(context);
        }
    }
}
