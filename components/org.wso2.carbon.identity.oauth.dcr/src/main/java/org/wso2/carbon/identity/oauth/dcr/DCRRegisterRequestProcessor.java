package org.wso2.carbon.identity.oauth.dcr;



import org.json.JSONObject;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundResponse;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dcr.profile.RegistrationProfile;
import org.wso2.carbon.identity.oauth.dcr.util.DCRConstants;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.HttpHeaders;
import java.util.HashMap;
import java.util.regex.Matcher;

/**
 * Created by yasiru on 4/20/16.
 */
public class DCRRegisterRequestProcessor extends InboundProcessor {

    @Override
    public InboundResponse process(InboundRequest inboundRequest) {
        DCRRegisterInboundRequest dcrRegisterInboundRequest = (DCRRegisterInboundRequest)inboundRequest;
        InboundResponse.InboundResponseBuilder inboundResponseBuilder = new InboundResponse.InboundResponseBuilder();
        RegistrationProfile registrationProfile = new RegistrationProfile();

        registrationProfile.setOwner(dcrRegisterInboundRequest.getOwner());
        registrationProfile.setClientName(dcrRegisterInboundRequest.getClientName());
        registrationProfile.setGrantType(dcrRegisterInboundRequest.getGrantType());
        registrationProfile.setCallbackUrl(dcrRegisterInboundRequest.getCallbackUrl());
        registrationProfile.setSaasApp(dcrRegisterInboundRequest.isSaasApp());

        DynamicClientRegistrationService dynamicClientRegistrationService =
                (DynamicClientRegistrationService) PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getOSGiService(DynamicClientRegistrationService.class, null);
        try {

            OAuthApplicationInfo applicationInfo = dynamicClientRegistrationService.
                    registerOAuthApplication(registrationProfile);


            inboundResponseBuilder.setBody(applicationInfo.toString());
            inboundResponseBuilder.setStatusCode(HttpServletResponse.SC_CREATED);
            inboundResponseBuilder.addHeader(OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL,
                    OAuthConstants.HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE);
            inboundResponseBuilder.addHeader(OAuthConstants.HTTP_RESP_HEADER_PRAGMA,
                    OAuthConstants.HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE);
            inboundResponseBuilder.addHeader("Content-Type", "application/json");


        } catch (DynamicClientRegistrationException e) {

        }
        return inboundResponseBuilder.build();
    }

    @Override
    public String getName() {
        return "Dynamic Configuration Request Processor";
    }

    @Override
    public String getCallbackPath(InboundMessageContext inboundMessageContext) {
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
    public boolean canHandle(InboundRequest inboundRequest) {
        if(inboundRequest != null) {
            Matcher matcher = DCRConstants.DCR_ENDPOINT_REGISTER_URL_PATTERN.matcher(inboundRequest.getRequestURI());
            if(matcher.matches()) {
                return true;
            }
        }
        return false;
    }
}
