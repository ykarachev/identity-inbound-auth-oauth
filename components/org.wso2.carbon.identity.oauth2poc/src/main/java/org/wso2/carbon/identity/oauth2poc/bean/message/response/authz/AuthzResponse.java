package org.wso2.carbon.identity.oauth2poc.bean.message.response.authz;

import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.wso2.carbon.identity.framework.IdentityResponse;
import org.wso2.carbon.identity.framework.authentication.context.AuthenticationContext;


public class AuthzResponse extends ROApprovalResponse {

    private OAuthASResponse.OAuthAuthorizationResponseBuilder builder;

    protected AuthzResponse(IdentityResponse.IdentityResponseBuilder builder) {
        super(builder);
        this.builder = ((AuthzResponseBuilder)builder).builder;
    }

    public OAuthASResponse.OAuthAuthorizationResponseBuilder getBuilder() {
        return this.builder;
    }

    public static class AuthzResponseBuilder extends ROApprovalResponseBuilder {

        public AuthzResponseBuilder(AuthenticationContext context) {
            super(context);
        }

        private OAuthASResponse.OAuthAuthorizationResponseBuilder builder;

        public OAuthASResponse.OAuthAuthorizationResponseBuilder getBuilder() {
            return builder;
        }

        public AuthzResponseBuilder setOLTUAuthzResponseBuilder(OAuthASResponse.OAuthAuthorizationResponseBuilder
                                                                        builder) {
            this.builder = builder;
            return this;
        }

        public AuthzResponse build() {
            return new AuthzResponse(this);
        }
    }
}
