package org.wso2.carbon.identity.oidc.dcr.processor.register;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.oauth.dcr.DCRManagementService;
import org.wso2.carbon.identity.oauth.dcr.processor.register.model.RegistrationResponseProfile;
import org.wso2.carbon.identity.oauth.dcr.processor.register.model.RegistrationRequest;
import org.wso2.carbon.identity.oidc.dcr.internal.OIDCDCRDataHolder;
import org.wso2.carbon.identity.oidc.dcr.processor.register.model.OIDCRegistrationRequest;
import org.wso2.carbon.identity.oidc.dcr.processor.register.model.OIDCRegistrationRequestProfile;
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
            OIDCRegistrationRequest registerRequest = (OIDCRegistrationRequest) identityRequest;
            OIDCRegistrationRequestProfile registrationProfile = (OIDCRegistrationRequestProfile)registerRequest.getRegistrationRequestProfile();
            registrationProfile.setTenantDomain(registerRequest.getTenantDomain());

            DCRManagementService
                    dcrManagementService = OIDCDCRDataHolder.getInstance().getDcrManagementService();

            RegistrationResponseProfile registrationResponseProfile = dcrManagementService.registerOAuthApplication(registrationProfile);
            dcrRegisterResponseBuilder = new OIDCRegistrationResponse.OIDCRegisterResponseBuilder();
            dcrRegisterResponseBuilder.setRegistrationResponseProfile(registrationResponseProfile);

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
