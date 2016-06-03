package org.wso2.carbon.identity.oauth.dcr.register;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.oauth.dcr.DCRException;
import org.wso2.carbon.identity.oauth.dcr.DCRService;
import org.wso2.carbon.identity.oauth.dcr.internal.DynamicClientRegistrationDataHolder;
import org.wso2.carbon.identity.oauth.dcr.model.OAuthApplication;
import org.wso2.carbon.identity.oauth.dcr.profile.RegistrationProfile;
import org.wso2.carbon.identity.oauth.dcr.util.DCRConstants;

import java.util.regex.Matcher;

public class DCRegisterRequestProcessor extends IdentityProcessor {

    private static Log log = LogFactory.getLog(DCRegisterRequestProcessor.class);
    @Override
    public IdentityResponse.IdentityResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {

        if(log.isDebugEnabled()){
            log.debug("Request processing started by DCRegisterRequestProcessor.");
        }
        DCRegisterRequest dcRegisterRequest = (DCRegisterRequest)identityRequest ;
        RegistrationProfile registrationProfile = new RegistrationProfile();

        registrationProfile.setOwner(dcRegisterRequest.getOwner());
        registrationProfile.setClientName(dcRegisterRequest.getClientName());
        registrationProfile.setGrantType(dcRegisterRequest.getGrantType());
        registrationProfile.setCallbackUrl(dcRegisterRequest.getCallbackUrl());
        registrationProfile.setSaasApp(dcRegisterRequest.isSaasApp());

        DCRService dcrService = DynamicClientRegistrationDataHolder.getInstance().getDcrService();


        DCRegisterResponse.DCRRegisterResponseBuilder dcrRegisterResponseBuilder = new DCRegisterResponse.DCRRegisterResponseBuilder();
        try {

            OAuthApplication oAuthApplication = dcrService.
                    registerOAuthApplication(registrationProfile);
            dcrRegisterResponseBuilder.setOAuthApplication(oAuthApplication);

            /*
            dcrRegisterResponseBuilder.setBody(applicationInfo.toString());
            dcrRegisterResponseBuilder.setStatusCode(HttpServletResponse.SC_CREATED);
            dcrRegisterResponseBuilder.addHeader(OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL,
                                             OAuthConstants.HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE);
            dcrRegisterResponseBuilder.addHeader(OAuthConstants.HTTP_RESP_HEADER_PRAGMA,
                                             OAuthConstants.HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE);
            dcrRegisterResponseBuilder.addHeader("Content-Type", "application/json");

            */
        } catch (DCRException e) {
            String errorMessage = "Error occurred file registering application, " + e.getMessage() ;
            log.error(errorMessage);
            throw new DCRException(errorMessage, e);
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
            log.debug("canExceptionHandle "+ canHandle +" by DCRegisterRequestProcessor.");
        }
        return canHandle;
    }


}
