/*
 *  Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2poc.model;

import org.apache.axiom.om.OMElement;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import javax.xml.namespace.QName;

public class OAuth2ServerConfig {

    private static Log log = LogFactory.getLog(OAuth2ServerConfig.class);

    private static OAuth2ServerConfig instance = new OAuth2ServerConfig();

    private OAuth2ServerConfig() {
        buildOAuthServerConfig();
    }

    public static OAuth2ServerConfig getInstance() {
        return instance;
    }

    private static final String CONFIG_ELEM_OAUTH = "OAuth2";

    private static String consentPageURL = null;
    private static String errorPageURL = null;
    private long userAccessTokenValidity = 3600;
    private boolean isSkipConsentPage = false;

    private void buildOAuthServerConfig() {

        IdentityConfigParser configParser = IdentityConfigParser.getInstance();
        OMElement oauthElem = configParser.getConfigElement(CONFIG_ELEM_OAUTH);

        if (oauthElem == null) {
            log.warn("OAuth2 element is not available. Initializing with default values for OAuth2 configurations");
            return;
        }

        // read OAuth URLs
        parseOAuth2URLs(oauthElem);

        // read default timeout periods
        parseDefaultValidityPeriods(oauthElem);
    }

    public String getConsentPageURL() {
        return consentPageURL;
    }

    public String getErrorPageURL() {
        return errorPageURL;
    }

    public long getUserAccessTokenValidity() {
        return userAccessTokenValidity;
    }

    public boolean isSkipConsentPage() {
        return isSkipConsentPage;
    }

    private void parseOAuth2URLs(OMElement oauth2Elem) {

        OMElement elem = oauth2Elem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.OAUTH2_CONSENT_PAGE_URL));
        if(elem != null){
            if(StringUtils.isNotBlank(elem.getText())) {
                consentPageURL = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauth2Elem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.OAUTH2_ERROR_PAGE_URL));
        if(elem != null){
            if(StringUtils.isNotBlank(elem.getText())) {
                errorPageURL = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
    }

    private void parseDefaultValidityPeriods(OMElement oauth2Elem) {

        OMElement userAccessTokenValidity = oauth2Elem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.USER_ACCESS_TOKEN_DEFAULT_VALIDITY_PERIOD));
        if (userAccessTokenValidity != null) {
            try {
                this.userAccessTokenValidity = Long.parseLong(userAccessTokenValidity.getText());
            } catch (NumberFormatException e) {
                log.error("Error occurred while parsing " + ConfigElements.USER_ACCESS_TOKEN_DEFAULT_VALIDITY_PERIOD
                        + " configuration. Initializing to default value 3600s.");
            }
        } else {
            if(log.isDebugEnabled()){
                log.debug(ConfigElements.USER_ACCESS_TOKEN_DEFAULT_VALIDITY_PERIOD + " was not found in identity.xml" +
                        ". Initializing to default value 3600s.");
            }
        }
    }

    /**
     * Localpart names for the OAuth2 configurations in identity.xml.
     */
    private class ConfigElements {

        // URLs
        public static final String OAUTH2_CONSENT_PAGE_URL = "OAuth2ConsentPage";
        public static final String OAUTH2_ERROR_PAGE_URL = "OAuth2ErrorPage";

        // Default validity periods
        private static final String USER_ACCESS_TOKEN_DEFAULT_VALIDITY_PERIOD = "UserAccessTokenDefaultValidityPeriod";
    }

    private QName getQNameWithIdentityNS(String localPart) {
        return new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, localPart);
    }
}
