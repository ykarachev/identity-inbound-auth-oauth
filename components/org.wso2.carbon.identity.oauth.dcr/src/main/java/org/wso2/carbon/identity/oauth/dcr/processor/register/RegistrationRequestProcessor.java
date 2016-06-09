package org.wso2.carbon.identity.oauth.dcr.processor.register;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.oauth.dcr.DCRManagementService;
import org.wso2.carbon.identity.oauth.dcr.internal.DCRDataHolder;
import org.wso2.carbon.identity.oauth.dcr.processor.register.model.RegistrationRequest;
import org.wso2.carbon.identity.oauth.dcr.processor.register.model.RegistrationRequestProfile;
import org.wso2.carbon.identity.oauth.dcr.processor.register.model.RegistrationResponse;
import org.wso2.carbon.identity.oauth.dcr.processor.register.model.RegistrationResponseProfile;
import org.wso2.carbon.identity.oauth.dcr.util.DCRConstants;

import java.util.regex.Matcher;

public class RegistrationRequestProcessor extends IdentityProcessor {

    private static Log log = LogFactory.getLog(RegistrationRequestProcessor.class);
    @Override
    public IdentityResponse.IdentityResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {

        if (log.isDebugEnabled()) {
            log.debug("Request processing started by RegistrationRequestProcessor.");
        }
        RegistrationResponse.DCRRegisterResponseBuilder dcrRegisterResponseBuilder = null;
        try {
            RegistrationRequest registerRequest = (RegistrationRequest) identityRequest;
            RegistrationRequestProfile registrationRequestProfile = registerRequest.getRegistrationRequestProfile();
            registrationRequestProfile.setTenantDomain(registerRequest.getTenantDomain());
            DCRManagementService
                    DCRManagementService = DCRDataHolder.getInstance().getDCRManagementService();

            RegistrationResponseProfile registrationResponseProfile = DCRManagementService.registerOAuthApplication(registrationRequestProfile);

            dcrRegisterResponseBuilder = new RegistrationResponse.DCRRegisterResponseBuilder();
            dcrRegisterResponseBuilder.setRegistrationResponseProfile(registrationResponseProfile);

        } catch (FrameworkException e) {
            throw new RegistrationProcessorException("Error occurred file registering application.", e);
        }

        return dcrRegisterResponseBuilder;
    }



    @Override
    public String getName() {
        return "DCRProcessor";
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
            Matcher matcher = DCRConstants.DCR_ENDPOINT_REGISTER_URL_PATTERN.matcher(identityRequest.getRequestURI());
            if (matcher.matches()) {
                canHandle =  true;
            }
        }
        if(log.isDebugEnabled()){
            log.debug("canHandle "+ canHandle +" by RegistrationRequestProcessor.");
        }
        return canHandle;
    }

}
