package org.wso2.carbon.identity.oidc.dcr.processor.register;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.oauth.dcr.DCRManagementService;
import org.wso2.carbon.identity.oauth.dcr.processor.register.model.OAuthApplication;
import org.wso2.carbon.identity.oauth.dcr.processor.register.model.RegistrationRequest;
import org.wso2.carbon.identity.oidc.dcr.internal.OIDCDCRDataHolder;
import org.wso2.carbon.identity.oidc.dcr.processor.register.model.OIDCRegistrationProfile;
import org.wso2.carbon.identity.oidc.dcr.processor.register.model.OIDCRegistrationResponse;
import org.wso2.carbon.identity.oidc.dcr.util.OIDCDCRConstants;

import java.util.regex.Matcher;

public class OIDCRegistrationRequestProcessor extends IdentityProcessor {

    private static Log log = LogFactory.getLog(OIDCRegistrationRequestProcessor.class);
    @Override
    public IdentityResponse.IdentityResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {

        if (log.isDebugEnabled()) {
            log.debug("Request processing started by OIDCRegistrationRequestProcessor.");
        }
        OIDCRegistrationResponse.OIDCRegisterResponseBuilder dcrRegisterResponseBuilder = null;
        try {
            RegistrationRequest registerRequest = (RegistrationRequest) identityRequest;
            OIDCRegistrationProfile registrationProfile = new OIDCRegistrationProfile();

            registrationProfile.setOwner(registerRequest.getOwner());
            registrationProfile.setClientName(registerRequest.getClientName());
            registrationProfile.setGrantType(registerRequest.getGrantType());
            registrationProfile.setRedirectUris(registerRequest.getRedirectUris());


            DCRManagementService
                    dcrManagementService = OIDCDCRDataHolder.getInstance().getDcrManagementService();

            OAuthApplication oAuthApplication = dcrManagementService.registerOAuthApplication(registrationProfile);
            dcrRegisterResponseBuilder = new OIDCRegistrationResponse.OIDCRegisterResponseBuilder();
            dcrRegisterResponseBuilder.setRedirectUris(oAuthApplication.getRedirectUrls());
            dcrRegisterResponseBuilder.setClientId(oAuthApplication.getClientId());
            dcrRegisterResponseBuilder.setClientName(oAuthApplication.getClientName());
            dcrRegisterResponseBuilder.setClientSecret(oAuthApplication.getClientSecret());

        } catch (FrameworkException e) {
            throw new OIDCRegistrationProcessorException("Error occurred file registering application.", e);
        }

        return dcrRegisterResponseBuilder;
    }



    @Override
    public String getName() {
        return "OIDCDCRProcessor";
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
        boolean canHandle = false ;
        if (identityRequest != null) {
            Matcher matcher = OIDCDCRConstants.OIDC_DCR_ENDPOINT_REGISTER_URL_PATTERN.matcher(identityRequest.getRequestURI());
            if (matcher.matches()) {
                canHandle =  true;
            }
        }
        if(log.isDebugEnabled()){
            log.debug("canHandle "+ canHandle +" by OIDCRegistrationRequestProcessor.");
        }
        return canHandle;
    }


}
