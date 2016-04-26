package org.wso2.carbon.identity.oauth.dcr;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkRuntimeException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundRequestFactory;
import org.wso2.carbon.identity.oauth.dcr.util.DCRConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Reader;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;

/**
 * Created by yasiru on 4/18/16.
 */
public class DCRInboundRequestFactory extends InboundRequestFactory {
    private static final Log log = LogFactory.getLog(DCRInboundRequestFactory.class);

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) throws FrameworkRuntimeException {
        if (request != null) {
            Matcher matcher = DCRConstants.DCR_ENDPOINT_URL_PATTERN.matcher(request.getRequestURI());
            if (matcher.matches()) {
                return true;
            }
        }
        return false;
    }

    @Override
    public InboundRequest create(HttpServletRequest request, HttpServletResponse response) {

        if ("POST".equals(request.getMethod())) { //if this is a registration request, decode json body
            return buildRegisterInboundRequest(request);
        } else if ("DELETE".equals(request.getMethod())) {
            return buildUnregisterRequest(request);
        } else {
            //TODO: Unsupported request
            return null;
        }
    }

    private DCRRegisterInboundRequest buildRegisterInboundRequest(HttpServletRequest request) {
        //DCR is interested only on auth headers and request body, and no cookies are used since the API is ReSTful.
        Map<String, String> headers = new HashMap<>(); //TODO: evaluate thread safety and replace with concurrenhashmap
        JSONParser jsonParser = new JSONParser(); //TODO:replace with a faster JSON parser like jackson or Boon
        headers.put("Authorization", request.getHeader("Authorization"));//TODO:get these from a static constant

        DCRRegisterInboundRequest.DCRRegisterInboundRequestBuilder registerRequestBuilder = new
                DCRRegisterInboundRequest.DCRRegisterInboundRequestBuilder();

        try {
            // Set the headers and request URI's before processing the json payload (which sometimes will not be
            // passable).
            // requestURI is used by the DCR Register processor to evaluate if the request is processable.
            registerRequestBuilder.setHeaders(headers);
            registerRequestBuilder.setRequestURI(request.getRequestURI());
            registerRequestBuilder.setMethod(request.getMethod());
            Reader requestBodyReader = request.getReader();
            JSONObject jsonData = (JSONObject) jsonParser.parse(requestBodyReader);

            registerRequestBuilder.setClientName((String) jsonData.get("clientName"));
            registerRequestBuilder.setCallbackUrl((String) jsonData.get("callbackUrl"));
            registerRequestBuilder.setTokenScope((String) jsonData.get("tokenScope"));
            registerRequestBuilder.setOwner((String) jsonData.get("owner"));
            registerRequestBuilder.setGrantType((String) jsonData.get("grantType"));
            registerRequestBuilder.setSaasApp((Boolean) jsonData.get("saasApp"));
        } catch (IOException e) {

        } catch (ParseException e) {
            //These will be handled by the request processor
        } finally {
            return registerRequestBuilder.build();
        }
    }

    private DCRUnregisterInboundRequest buildUnregisterRequest(HttpServletRequest request) {
        //DCR is interested only on auth headers and request body, and no cookies are used since the API is ReSTful.
        Map<String, String> headers = new HashMap<>(); //TODO: evaluate thread safety and replace with concurrenhashmap
        headers.put("Authorization", request.getHeader("Authorization"));//TODO:get these from a static constant

        DCRUnregisterInboundRequest.DCRInboundUnregisterInboundRequestBuilder unregisterRequestBuilder =
                new DCRUnregisterInboundRequest.DCRInboundUnregisterInboundRequestBuilder();;

        unregisterRequestBuilder.setMethod(request.getMethod());
        unregisterRequestBuilder.setHeaders(headers);

        String clientId = request.getParameter(DCRConstants.ClientMetadata.OAUTH_CLIENT_ID);
        String applicationName = request.getParameter("applicationName");
        String consumerKey = null;
        Matcher matcher = DCRConstants.DCR_ENDPOINT_UNREGISTER_URL_PATTERN.matcher(request.getRequestURI());
        if (matcher.find()) {
            consumerKey = matcher.group(0);
        }

        unregisterRequestBuilder.setApplicationName(applicationName);
        unregisterRequestBuilder.setUserId(clientId);
        unregisterRequestBuilder.setConsumerKey(consumerKey);
        return unregisterRequestBuilder.build();
    }
}
