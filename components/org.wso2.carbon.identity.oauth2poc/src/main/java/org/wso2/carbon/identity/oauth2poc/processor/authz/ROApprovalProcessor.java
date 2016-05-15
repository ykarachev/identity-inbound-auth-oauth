/*
 *  Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2poc.processor.authz;

import org.apache.commons.lang3.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundUtil;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.oauth2poc.OAuth2;
import org.wso2.carbon.identity.oauth2poc.bean.context.OAuth2AuthzMessageContext;
import org.wso2.carbon.identity.oauth2poc.bean.message.request.authz.OAuth2AuthzRequest;
import org.wso2.carbon.identity.oauth2poc.bean.message.response.authz.ConsentResponse;
import org.wso2.carbon.identity.oauth2poc.bean.message.response.authz.ROApprovalResponse;
import org.wso2.carbon.identity.oauth2poc.exception.OAuth2AuthnException;
import org.wso2.carbon.identity.oauth2poc.exception.OAuth2ConsentException;
import org.wso2.carbon.identity.oauth2poc.exception.OAuth2Exception;
import org.wso2.carbon.identity.oauth2poc.exception.OAuth2InternalException;
import org.wso2.carbon.identity.oauth2poc.model.OAuth2ServerConfig;
import org.wso2.carbon.identity.oauth2poc.util.OAuth2ConsentStore;

import java.util.UUID;

public abstract class ROApprovalProcessor extends IdentityProcessor {

    @Override
    public String getName() {
        return "ROApprovalProcessor";
    }

    @Override
    public String getCallbackPath(IdentityMessageContext context) {
        return null;
    }

    @Override
    public String getRelyingPartyId() {
        return null;
    }

    @Override
    public int getPriority() {
        return 0;
    }

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {

        IdentityMessageContext context = getContextIfAvailable(identityRequest);
        if(context != null) {
            if(context.getRequest() instanceof OAuth2AuthzRequest){
                return true;
            }
        }
        return false;
    }

    @Override
    public ROApprovalResponse.ROApprovalResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {

        OAuth2AuthzMessageContext messageContext = (OAuth2AuthzMessageContext)getContextIfAvailable(identityRequest);

        if(messageContext.getAuthzUser() == null) { // authentication response

            messageContext.addParameter(OAuth2.OAUTH2_RESOURCE_OWNER_AUTHN_REQUEST, identityRequest);
            AuthenticationResult authnResult = processResponseFromFrameworkLogin(messageContext);

            AuthenticatedUser authenticatedUser = null;
            if(authnResult.isAuthenticated()) {
                authenticatedUser = authnResult.getSubject();
                messageContext.setAuthzUser(authenticatedUser);

            } else {
                throw OAuth2AuthnException.error("Resource owner authentication failed");
            }

            if (!OAuth2ServerConfig.getInstance().isSkipConsentPage()) {

                String spName = ((ServiceProvider) messageContext.getParameter(OAuth2.OAUTH2_SERVICE_PROVIDER)).getApplicationName();

                if (!OAuth2ConsentStore.getInstance().hasUserApprovedAppAlways(authenticatedUser, spName)) {
                    return initiateResourceOwnerConsent(messageContext);
                } else {
                    messageContext.addParameter(OAuth2.CONSENT, "ApproveAlways");
                }
            } else {
                messageContext.addParameter(OAuth2.CONSENT, "SkipOAuth2Consent");
            }

        }

        // if this line is reached that means this is a consent response or consent is skipped due config or approve
        // always. We set the inbound request to message context only if it has gone through consent process
        // if consent consent was skipped due to configuration or approve always,
        // authenticated request and authorized request are the same
        if(!StringUtils.equals("ApproveAlways", (String)messageContext.getParameter(OAuth2.CONSENT)) &&
                !StringUtils.equals("SkipOAuth2Consent", (String)messageContext.getParameter(OAuth2.CONSENT))) {
            messageContext.addParameter(OAuth2.OAUTH2_RESOURCE_OWNER_AUTHZ_REQUEST, identityRequest);
            processConsent(messageContext);
        }
        return buildAuthzResponse(messageContext);
    }

    /**
     * Initiate the request to obtain authorization decision from resource owner
     *
     * @param messageContext The runtime message context
     * @return OAuth2 authorization endpoint
     */
    protected ConsentResponse.ConsentResponseBuilder initiateResourceOwnerConsent(OAuth2AuthzMessageContext messageContext) {

        String sessionDataKeyConsent = UUID.randomUUID().toString();
        InboundUtil.addContextToCache(sessionDataKeyConsent, messageContext);

        ConsentResponse.ConsentResponseBuilder builder = new ConsentResponse.ConsentResponseBuilder(messageContext);
        builder.setSessionDataKeyConsent(sessionDataKeyConsent);
        builder.setApplicationName(((ServiceProvider)messageContext.getParameter(OAuth2.OAUTH2_SERVICE_PROVIDER))
                                           .getApplicationName());
        builder.setAuthenticatedSubjectId(messageContext.getAuthzUser().getAuthenticatedSubjectIdentifier());
        builder.setRequestedScopes(messageContext.getRequest().getScopes());
        builder.setParameterMap(messageContext.getRequest().getParameterMap());
        return builder;
    }

    /**
     * Process the response from resource owner approval process and establish the authorization decision
     *
     * @param messageContext The runtime message context
     * @throws org.wso2.carbon.identity.oauth2poc.exception.OAuth2Exception Exception occurred while processing resource owner approval
     */
    protected void processConsent(OAuth2AuthzMessageContext messageContext) throws OAuth2Exception {

        String consent = messageContext.getRequest().getParameter(OAuth2.CONSENT);
        String spName = ((ServiceProvider)messageContext.getParameter(OAuth2.OAUTH2_SERVICE_PROVIDER)).getApplicationName();
        if (StringUtils.isNotBlank(consent)) {
            if(StringUtils.equals("ApproveAlways", consent)) {
                OAuth2ConsentStore.getInstance().approveAppAlways(messageContext.getAuthzUser(), spName, true);
            } else {

            }
        } else if(StringUtils.equals("Deny", consent)) {
            OAuth2ConsentStore.getInstance().approveAppAlways(messageContext.getAuthzUser(), spName, false);
            throw OAuth2ConsentException.error("User denied the request");
        } else {
            throw OAuth2InternalException.error("Cannot find consent parameter");
        }
    }

    /**
     * Issues the authorization endpoint response
     *
     * @param messageContext The runtime message context
     * @return OAuth2 authorization endpoint response
     */
    protected abstract ROApprovalResponse.ROApprovalResponseBuilder buildAuthzResponse(OAuth2AuthzMessageContext messageContext);
}
