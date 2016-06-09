package org.wso2.carbon.identity.oauth.dcr.processor.unregister;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.oauth.dcr.DCRManagementException;
import org.wso2.carbon.identity.oauth.dcr.DCRManagementService;
import org.wso2.carbon.identity.oauth.dcr.internal.DCRDataHolder;
import org.wso2.carbon.identity.oauth.dcr.processor.unregister.model.UnregistrationRequest;
import org.wso2.carbon.identity.oauth.dcr.processor.unregister.model.UnregistrationResponse;
import org.wso2.carbon.identity.oauth.dcr.util.DCRConstants;

import java.util.regex.Matcher;

public class UnregistrationRequestProcessor extends IdentityProcessor{
    private static Log log = LogFactory.getLog(UnregistrationRequestProcessor.class);

    @Override
    public IdentityResponse.IdentityResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {

        UnregistrationResponse.DCUnregisterResponseBuilder dcUnregisterResponseBuilder = null ;
        try {
            UnregistrationRequest unregistrationRequest = (UnregistrationRequest)identityRequest ;
            dcUnregisterResponseBuilder = new UnregistrationResponse.DCUnregisterResponseBuilder();

            DCRManagementService
                    DCRManagementService = DCRDataHolder.getInstance().getDCRManagementService();

            DCRManagementService.unregisterOAuthApplication(unregistrationRequest.getUserId(),
                                                                           unregistrationRequest
                                                                                   .getApplicationName(), unregistrationRequest
                                                                                   .getConsumerKey());
        } catch (DCRManagementException e) {
            throw new UnregistrationProcessorException("Error occured while processing the request.", e);
        }
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
            log.debug("canHandle "+ canHandle +" by UnregistrationRequestProcessor.");
        }
        return canHandle;
    }
}
