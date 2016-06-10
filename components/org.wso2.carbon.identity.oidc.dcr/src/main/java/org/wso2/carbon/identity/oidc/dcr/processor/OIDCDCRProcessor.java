package org.wso2.carbon.identity.oidc.dcr.processor;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.oauth.dcr.DCRManagementService;
import org.wso2.carbon.identity.oauth.dcr.processor.DCRProcessor;
import org.wso2.carbon.identity.oidc.dcr.util.OIDCDCRConstants;

import java.util.regex.Matcher;

public class OIDCDCRProcessor extends DCRProcessor {

    private static Log log = LogFactory.getLog(OIDCDCRProcessor.class);
    @Override
    public IdentityResponse.IdentityResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {

        if (log.isDebugEnabled()) {
            log.debug("Request processing started by OIDCDCRProcessor.");
        }
        return super.process(identityRequest);
    }

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        boolean canHandle = false ;
        if (identityRequest != null) {
            Matcher registerMatcher = OIDCDCRConstants.OIDC_DCR_ENDPOINT_REGISTER_URL_PATTERN.matcher(identityRequest.getRequestURI());
            if (registerMatcher.matches()) {
                canHandle =  true;
            }
        }
        if(log.isDebugEnabled()){
            log.debug("canHandle "+ canHandle +" by OIDCDCRProcessor.");
        }
        return canHandle;
    }


}
