package org.wso2.carbon.identity.oauth.dcr;

import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundResponse;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dcr.util.DCRConstants;

import javax.servlet.http.HttpServletResponse;
import java.util.Map;
import java.util.regex.Matcher;

/**
 * Created by yasiru on 4/22/16.
 */
public class DCRUnregisterRequestProcessor extends InboundProcessor {
    @Override
    public InboundResponse process(InboundRequest inboundRequest) {
        InboundResponse.InboundResponseBuilder inboundResponseBuilder = new InboundResponse.InboundResponseBuilder();
        DCRUnregisterInboundRequest unregisterRequest = (DCRUnregisterInboundRequest)inboundRequest;
        DynamicClientRegistrationService dynamicClientRegistrationService =
                (DynamicClientRegistrationService) PrivilegedCarbonContext.getThreadLocalCarbonContext()
                        .getOSGiService(DynamicClientRegistrationService.class, null);

        try {

            boolean result = dynamicClientRegistrationService.unregisterOAuthApplication(unregisterRequest.getUserId(),
                    unregisterRequest.getApplicationName(), unregisterRequest.getConsumerKey());
            if(result) { //success
                inboundResponseBuilder.setStatusCode(HttpServletResponse.SC_NO_CONTENT);
                inboundResponseBuilder.addHeader(OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL,
                        OAuthConstants.HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE);
                inboundResponseBuilder.addHeader(OAuthConstants.HTTP_RESP_HEADER_PRAGMA,
                        OAuthConstants.HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE);
            }
        } catch (DynamicClientRegistrationException e) {
            //TODO: Handle this
        } finally {
            return inboundResponseBuilder.build();
        }

    }

    @Override
    public String getName() {
        return null;
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
        if(inboundRequest != null && inboundRequest instanceof DCRUnregisterInboundRequest ) {
            return true;
        }
        return false;
    }
}
