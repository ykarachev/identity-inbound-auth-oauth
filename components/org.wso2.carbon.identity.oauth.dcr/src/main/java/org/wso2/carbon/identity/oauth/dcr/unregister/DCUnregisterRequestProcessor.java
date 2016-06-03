package org.wso2.carbon.identity.oauth.dcr.unregister;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.oauth.dcr.DCRService;
import org.wso2.carbon.identity.oauth.dcr.internal.DynamicClientRegistrationDataHolder;
import org.wso2.carbon.identity.oauth.dcr.util.DCRConstants;

import java.util.regex.Matcher;

public class DCUnregisterRequestProcessor extends IdentityProcessor{
    private static Log log = LogFactory.getLog(DCUnregisterRequestProcessor.class);

    @Override
    public IdentityResponse.IdentityResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {
        DCUnregisterRequest dcUnregisterRequest = (DCUnregisterRequest)identityRequest ;
        DCUnregisterResponse.DCUnregisterResponseBuilder dcUnregisterResponseBuilder = new DCUnregisterResponse.DCUnregisterResponseBuilder();

        DCRService dcrService = DynamicClientRegistrationDataHolder.getInstance().getDcrService();

        boolean isUnregistered = dcrService.unregisterOAuthApplication(dcUnregisterRequest.getUserId(),
                                                                       dcUnregisterRequest.getApplicationName(), dcUnregisterRequest.getConsumerKey());
        dcUnregisterResponseBuilder.setIsUnregistered(isUnregistered);
            /*if(result) {

                inboundResponseBuilder.setStatusCode(HttpServletResponse.SC_NO_CONTENT);
                inboundResponseBuilder.addHeader(OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL,
                                                 OAuthConstants.HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE);
                inboundResponseBuilder.addHeader(OAuthConstants.HTTP_RESP_HEADER_PRAGMA,
                                                 OAuthConstants.HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE);
            }*/
        return dcUnregisterResponseBuilder ;
    }

    @Override
    public String getName() {
        return null;
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
            Matcher matcher = DCRConstants.DCR_ENDPOINT_UNREGISTER_URL_PATTERN.matcher(identityRequest.getRequestURI());
            if (matcher.matches()) {
                canHandle =  true;
            }
        }
        if(log.isDebugEnabled()){
            log.debug("canHandle "+ canHandle +" by DCUnregisterRequestProcessor.");
        }
        return canHandle;
    }
}
