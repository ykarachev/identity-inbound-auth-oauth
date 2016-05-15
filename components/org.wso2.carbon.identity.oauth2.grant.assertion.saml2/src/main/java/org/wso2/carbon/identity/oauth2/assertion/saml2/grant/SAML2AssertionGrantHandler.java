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

package org.wso2.carbon.identity.oauth2.assertion.saml2.grant;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.OAuth;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2TokenMessageContext;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2ClientException;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2InternalException;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2RuntimeException;
import org.wso2.carbon.identity.oauth2new.handler.grant.AuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2new.util.X509CredentialImpl;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class SAML2AssertionGrantHandler extends AuthorizationGrantHandler {

    private static Log log = LogFactory.getLog(SAML2AssertionGrantHandler.class);
    SAMLSignatureProfileValidator profileValidator = null;

    public void init(InitConfig initConfig) {
        super.init(initConfig);
        Thread thread = Thread.currentThread();
        ClassLoader loader = thread.getContextClassLoader();
        thread.setContextClassLoader(this.getClass().getClassLoader());
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            throw OAuth2RuntimeException.error("Error in bootstrapping the OpenSAML2 library");
        } finally {
            thread.setContextClassLoader(loader);
        }
        profileValidator = new SAMLSignatureProfileValidator();
    }



    @Override
    public boolean canHandle(MessageContext messageContext) {
        if(messageContext instanceof OAuth2TokenMessageContext) {
            if(SAML2GrantConstants.SAML2_GRANT_TYPE.equals(((OAuth2TokenMessageContext) messageContext).getRequest()
                    .getGrantType())) {
                return true;
            }
        }
        return false;
    }

    /**
     * We're validating the SAML token that we receive from the request. Through the assertion parameter is the POST
     * request. A request format that we handle here looks like,
     * <p/>
     * POST /token.oauth2 HTTP/1.1
     * Host: as.example.com
     * Content-Type: application/x-www-form-urlencoded
     * <p/>
     * grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Asaml2-bearer&
     * assertion=PHNhbWxwOl...[omitted for brevity]...ZT4
     *
     * @param messageContext The runtime message context
     * @throws OAuth2Exception
     */
    public void validateGrant(OAuth2TokenMessageContext messageContext) throws OAuth2ClientException, OAuth2Exception {

        super.validateGrant(messageContext);

        SAML2AssertionGrantRequest request = (SAML2AssertionGrantRequest)messageContext.getRequest();
        String assertionString = request.getAssertion();
        Assertion assertion = null;
        IdentityProvider identityProvider = null;
        String tokenEndpointAlias = null;
        String tenantDomain = request.getTenantDomain();

        // Logging the SAML token
        if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.SAML_ASSERTION)) {
            log.debug("Received SAML2 assertion : " + new String(Base64.decodeBase64(assertionString)));
        }


        try {
            XMLObject samlObject = IdentityUtil.unmarshall(new String(Base64.decodeBase64(assertionString)));
            assertion = (Assertion) samlObject;
        } catch (IdentityException e) {
            throw OAuth2ClientException.error(e.getMessage(), e);
        } catch (ClassCastException e) {
            throw OAuth2ClientException.error("XML object is not a SAML2 assertion", e);
        }

        /**
         * The Assertion MUST contain a <Subject> element.  The subject MAY identify the resource owner for whom
         * the access token is being requested.  For client authentication, the Subject MUST be the "client_id"
         * of the OAuth client.  When using an Assertion as an authorization grant, the Subject SHOULD identify
         * an authorized accessor for whom the access token is being requested (typically the resource owner, or
         * an authorized delegate).  Additional information identifying the subject/principal of the transaction
         * MAY be included in an <AttributeStatement>.
         */
        if (assertion.getSubject() != null) {
            String resourceOwnerUserName = assertion.getSubject().getNameID().getValue();
            if (StringUtils.isBlank(resourceOwnerUserName)) {
                throw OAuth2ClientException.error("NameID in Assertion cannot be empty");
            }
            messageContext.setAuthzUser(
                    AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(resourceOwnerUserName));
        } else {
            throw OAuth2ClientException.error("Cannot find a Subject in the Assertion");
        }

        if (assertion.getIssuer() == null || StringUtils.isBlank(assertion.getIssuer().getValue())) {
            throw OAuth2ClientException.error("Issuer is empty in the SAML assertion");
        } else {
            try {
                identityProvider = IdentityProviderManager.getInstance().
                        getIdPByAuthenticatorPropertyValue("IdPEntityId",
                                assertion.getIssuer().getValue(), tenantDomain, false);
                // IF Federated IDP not found get the resident IDP and check,
                // resident IDP entitiID == issuer
                if (identityProvider != null) {
                    if (IdentityApplicationConstants.RESIDENT_IDP_RESERVED_NAME.equals(
                            identityProvider.getIdentityProviderName())) {
                        identityProvider = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);

                        FederatedAuthenticatorConfig[] fedAuthnConfigs =
                                identityProvider.getFederatedAuthenticatorConfigs();
                        String idpEntityId = null;

                        // Get SAML authenticator
                        FederatedAuthenticatorConfig samlAuthenticatorConfig =
                                IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                                        IdentityApplicationConstants.Authenticator.SAML2SSO.NAME);
                        // Get Entity ID from SAML authenticator
                        Property samlProperty = IdentityApplicationManagementUtil.getProperty(
                                samlAuthenticatorConfig.getProperties(),
                                IdentityApplicationConstants.Authenticator.SAML2SSO.IDP_ENTITY_ID);
                        if (samlProperty != null) {
                            idpEntityId = samlProperty.getValue();
                        }

                        if (idpEntityId == null || !assertion.getIssuer().getValue().equals(idpEntityId)) {
                            throw OAuth2ClientException.error("SAML Token Issuer verification failed against resident Identity Provider " +
                                    "in tenant : " + tenantDomain + ". Received : " +
                                    assertion.getIssuer().getValue() + ", Expected : " + idpEntityId);
                        }

                        // Get OpenIDConnect authenticator == OAuth
                        // authenticator
                        FederatedAuthenticatorConfig oauthAuthenticatorConfig =
                                IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                                        IdentityApplicationConstants.Authenticator.OIDC.NAME);
                        // Get OAuth token endpoint
                        Property oauthProperty = IdentityApplicationManagementUtil.getProperty(
                                oauthAuthenticatorConfig.getProperties(),
                                IdentityApplicationConstants.Authenticator.OIDC.OAUTH2_TOKEN_URL);
                        if (oauthProperty != null) {
                            tokenEndpointAlias = oauthProperty.getValue();
                        }
                    } else {
                        // Get Alias from Federated IDP
                        tokenEndpointAlias = identityProvider.getAlias();
                    }
                } else {
                    throw OAuth2ClientException.error("SAML Token Issuer : " + assertion.getIssuer().getValue() +
                            " not registered as a local Identity Provider in tenant : " + tenantDomain);
                }
            } catch (IdentityProviderManagementException e) {
                throw OAuth2InternalException.error("Error while getting Federated Identity Provider", e);
            }
        }

        /**
         * The Assertion MUST contain <Conditions> element with an <AudienceRestriction> element with an <Audience>
         * element containing a URI reference that identifies the authorization server, or the service provider
         * SAML entity of its controlling domain, as an intended audience.  The token endpoint URL of the
         * authorization server MAY be used as an acceptable value for an <Audience> element.  The authorization
         * server MUST verify that it is an intended audience for the Assertion.
         */

        if (StringUtils.isBlank(tokenEndpointAlias)) {
            throw OAuth2ClientException.error("Token Endpoint alias has not been configured in the Identity Provider : "
                    + identityProvider.getIdentityProviderName() + " in tenant : " + tenantDomain);
        }

        Conditions conditions = assertion.getConditions();
        if (conditions != null) {
            //Set validity period extracted from SAML Assertion
            long curTimeInMillis = Calendar.getInstance().getTimeInMillis();
            messageContext.setValidityPeriod(conditions.getNotOnOrAfter().getMillis() - curTimeInMillis);
            List<AudienceRestriction> audienceRestrictions = conditions.getAudienceRestrictions();
            if (audienceRestrictions != null && !audienceRestrictions.isEmpty()) {
                boolean audienceFound = false;
                for (AudienceRestriction audienceRestriction : audienceRestrictions) {
                    if (CollectionUtils.isNotEmpty(audienceRestriction.getAudiences())) {
                        for (Audience audience : audienceRestriction.getAudiences()) {
                            if (audience.getAudienceURI().equals(tokenEndpointAlias)) {
                                audienceFound = true;
                                break;
                            }
                        }
                    }
                    if (audienceFound) {
                        break;
                    }
                }
                if (!audienceFound) {
                    throw OAuth2ClientException.error("SAML Assertion Audience Restriction validation failed against the Audience : " +
                            tokenEndpointAlias + " of Identity Provider : " +
                            identityProvider.getIdentityProviderName() + " in tenant : " + tenantDomain);
                }
            } else {
                throw OAuth2ClientException.error("SAML Assertion doesn't contain AudienceRestrictions");
            }
        } else {
            throw OAuth2ClientException.error("SAML Assertion doesn't contain Conditions");
        }


        /**
         * The Assertion MUST have an expiry that limits the time window during which it can be used.  The expiry
         * can be expressed either as the NotOnOrAfter attribute of the <Conditions> element or as the NotOnOrAfter
         * attribute of a suitable <SubjectConfirmationData> element.
         */

        /**
         * The <Subject> element MUST contain at least one <SubjectConfirmation> element that allows the
         * authorization server to confirm it as a Bearer Assertion.  Such a <SubjectConfirmation> element MUST
         * have a Method attribute with a value of "urn:oasis:names:tc:SAML:2.0:cm:bearer".  The
         * <SubjectConfirmation> element MUST contain a <SubjectConfirmationData> element, unless the Assertion
         * has a suitable NotOnOrAfter attribute on the <Conditions> element, in which case the
         * <SubjectConfirmationData> element MAY be omitted. When present, the <SubjectConfirmationData> element
         * MUST have a Recipient attribute with a value indicating the token endpoint URL of the authorization
         * server (or an acceptable alias).  The authorization server MUST verify that the value of the Recipient
         * attribute matches the token endpoint URL (or an acceptable alias) to which the Assertion was delivered.
         * The <SubjectConfirmationData> element MUST have a NotOnOrAfter attribute that limits the window during
         * which the Assertion can be confirmed.  The <SubjectConfirmationData> element MAY also contain an Address
         * attribute limiting the client address from which the Assertion can be delivered.  Verification of the
         * Address is at the discretion of the authorization server.
         */

        DateTime notOnOrAfterFromConditions = null;
        Set<DateTime> notOnOrAfterFromSubjectConfirmations = new HashSet<DateTime>();
        boolean bearerFound = false;
        List<String> recipientURLS = new ArrayList<>();

        if (assertion.getConditions() != null && assertion.getConditions().getNotOnOrAfter() != null) {
            notOnOrAfterFromConditions = assertion.getConditions().getNotOnOrAfter();
        }

        List<SubjectConfirmation> subjectConfirmations = assertion.getSubject().getSubjectConfirmations();
        if (subjectConfirmations != null && !subjectConfirmations.isEmpty()) {
            for (SubjectConfirmation s : subjectConfirmations) {
                if (s.getMethod() != null) {
                    if (s.getMethod().equals(SAML2GrantConstants.SAML2_BEARER_METHOD)) {
                        bearerFound = true;
                    }
                } else {
                    throw OAuth2ClientException.error("Cannot find Method attribute in SubjectConfirmation " + s
                            .toString());
                }

                if (s.getSubjectConfirmationData() != null) {
                    if (s.getSubjectConfirmationData().getRecipient() != null) {
                        recipientURLS.add(s.getSubjectConfirmationData().getRecipient());
                    }
                    if (s.getSubjectConfirmationData().getNotOnOrAfter() != null) {
                        notOnOrAfterFromSubjectConfirmations.add(s.getSubjectConfirmationData().getNotOnOrAfter());
                    } else {
                        throw OAuth2ClientException.error("Cannot find NotOnOrAfter attribute in SubjectConfirmationData " +
                                s.getSubjectConfirmationData().toString());
                    }
                } else if (s.getSubjectConfirmationData() == null && notOnOrAfterFromConditions == null) {
                    throw OAuth2ClientException.error("Neither can find NotOnOrAfter attribute in Conditions nor SubjectConfirmationData" +
                            "in SubjectConfirmation " + s.toString());
                }
            }
        } else {
            OAuth2ClientException.error("No SubjectConfirmation exist in Assertion");
        }

        if (!bearerFound) {
            throw OAuth2ClientException.error("Failed to find a SubjectConfirmation with a Method attribute having : " +
                    SAML2GrantConstants.SAML2_BEARER_METHOD);
        }

        if (CollectionUtils.isNotEmpty(recipientURLS) && !recipientURLS.contains(tokenEndpointAlias)) {
            throw OAuth2ClientException.error("None of the recipient URLs match against the token endpoint alias : " + tokenEndpointAlias +
                    " of Identity Provider " + identityProvider.getIdentityProviderName() + " in tenant : " +
                    tenantDomain);
        }

        /**
         * The authorization server MUST verify that the NotOnOrAfter instant has not passed, subject to allowable
         * clock skew between systems.  An invalid NotOnOrAfter instant on the <Conditions> element invalidates
         * the entire Assertion.  An invalid NotOnOrAfter instant on a <SubjectConfirmationData> element only
         * invalidates the individual <SubjectConfirmation>.  The authorization server MAY reject Assertions with
         * a NotOnOrAfter instant that is unreasonably far in the future.  The authorization server MAY ensure
         * that Bearer Assertions are not replayed, by maintaining the set of used ID values for the length of
         * time for which the Assertion would be considered valid based on the applicable NotOnOrAfter instant.
         */
        if (notOnOrAfterFromConditions != null && notOnOrAfterFromConditions.compareTo(new DateTime()) < 1) {
            // notOnOrAfter is an expired timestamp
            throw OAuth2ClientException.error("NotOnOrAfter is having an expired timestamp in Conditions element");
        }
        boolean validSubjectConfirmationDataExists = false;
        if (!notOnOrAfterFromSubjectConfirmations.isEmpty()) {
            for (DateTime entry : notOnOrAfterFromSubjectConfirmations) {
                if (entry.compareTo(new DateTime()) >= 1) {
                    validSubjectConfirmationDataExists = true;
                }
            }
        }
        if (notOnOrAfterFromConditions == null && !validSubjectConfirmationDataExists) {
            throw OAuth2ClientException.error("No valid NotOnOrAfter element found in SubjectConfirmations");
        }

        /**
         * The Assertion MUST be digitally signed by the issuer and the authorization server MUST verify the
         * signature.
         */

        try {
            profileValidator.validate(assertion.getSignature());
        } catch (ValidationException e) {
            // Indicates signature did not conform to SAML Signature profile
            throw OAuth2ClientException.error("Signature do not confirm to SAML signature profile.", e);
        }

        X509Certificate x509Certificate = null;
        try {
            x509Certificate = (X509Certificate) IdentityApplicationManagementUtil
                    .decodeCertificate(identityProvider.getCertificate());
        } catch (CertificateException e) {
            throw OAuth2ClientException.error("Error occurred while decoding public certificate of Identity Provider "
                    + identityProvider.getIdentityProviderName() + " for tenant domain " + tenantDomain);
        }

        try {
            X509Credential x509Credential = new X509CredentialImpl(x509Certificate);
            SignatureValidator signatureValidator = new SignatureValidator(x509Credential);
            signatureValidator.validate(assertion.getSignature());
            if (log.isDebugEnabled()){
                log.debug("Signature validation successful");
            }
        } catch (ValidationException e) {
            throw OAuth2ClientException.error("Error while validating the signature.", e);
        }

        /**
         * The authorization server MUST verify that the Assertion is valid in all other respects per
         * [OASIS.saml-core-2.0-os], such as (but not limited to) evaluating all content within the Conditions
         * element including the NotOnOrAfter and NotBefore attributes, rejecting unknown condition types, etc.
         *
         * [OASIS.saml-core-2.0-os] - http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
         */
        // TODO: Throw the SAML request through the general SAML2 validation routines
        messageContext.setApprovedScopes(request.getScopes());
        messageContext.addParameter(OAuth.OAUTH_ASSERTION, assertion);
    }

}
