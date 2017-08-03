/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.util;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.Charsets;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.KeyProviderService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;

import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Holds the public certificates per tenant.
 */
public class CertificatesStore {

    private static Map<Integer, Certificate> publicCerts = new ConcurrentHashMap<Integer, Certificate>();

    /**
     * Returns the Certificate given tenant Domain
     * @param tenantDomain
     * @param tenantId
     * @return
     * @throws Exception
     */
    public Certificate getCertificate(String tenantDomain, int tenantId) throws Exception {
        Certificate publicCert = publicCerts.get(tenantId);
        if(publicCert != null) {
            return publicCert;
        }
        KeyProviderService keyProviderService = OAuth2ServiceComponentHolder.getKeyProvider();
        if (keyProviderService != null) {
            publicCert = keyProviderService.getCertificate(tenantDomain);
        }

        if (publicCert == null) {
            publicCert = getCertificateWithCarbon(tenantDomain, tenantId);;
        }

        if (publicCert != null) {
            publicCerts.put(tenantId, publicCert);
        } else {
            String error = "Error in obtaining certificate for tenant " + tenantDomain;
            throw new IdentityOAuth2Exception(error);
        }

        return publicCert;
    }

    /**
     * Helper method to add public certificate to JWT_HEADER to signature verification.
     *
     * @param tenantDomain
     * @param tenantId
     * @throws IdentityOAuth2Exception
     */
    public String getThumbPrint(String tenantDomain, int tenantId) throws IdentityOAuth2Exception {

        try {

            Certificate certificate = getCertificate(tenantDomain, tenantId);

        // TODO: maintain a hashmap with tenants' pubkey thumbprints after first initialization

            //generate the SHA-1 thumbprint of the certificate
            MessageDigest digestValue = MessageDigest.getInstance("SHA-1");
            byte[] der = certificate.getEncoded();
            digestValue.update(der);
            byte[] digestInBytes = digestValue.digest();

            String publicCertThumbprint = Hex.encodeHexString(digestInBytes);
            String base64EncodedThumbPrint = new String(new Base64(0, null, true).encode(publicCertThumbprint
                    .getBytes(Charsets.UTF_8)), Charsets.UTF_8);
            return base64EncodedThumbPrint;

        } catch (Exception e) {
            String error = "Error in obtaining certificate for tenant " + tenantDomain;
            throw new IdentityOAuth2Exception(error, e);
        }
    }

    /**
     * Returns certificates from the carbon platform way using platform key manager
     *
     * @param tenantDomain
     * @param tenantId
     * @return
     * @throws Exception
     */
    private Certificate getCertificateWithCarbon(String tenantDomain, int tenantId) throws Exception {
        Certificate publicCert;
        if (tenantDomain == null) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }

        if (tenantId == 0) {
            tenantId = OAuth2Util.getTenantId(tenantDomain);
        }

        if (!(publicCerts.containsKey(tenantId))) {

            try {
                IdentityTenantUtil.initializeRegistry(tenantId, tenantDomain);
            } catch (IdentityException e) {
                throw new IdentityOAuth2Exception("Error occurred while loading registry for tenant: " + tenantDomain,
                        e);
            }

            // get tenant's key store manager
            KeyStoreManager tenantKSM = KeyStoreManager.getInstance(tenantId);

            KeyStore keyStore = null;
            if (!MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
                // derive key store name
                String ksName = tenantDomain.trim().replace(".", "-");
                String jksName = ksName + ".jks";
                keyStore = tenantKSM.getKeyStore(jksName);
                publicCert = keyStore.getCertificate(tenantDomain);
            } else {
                publicCert = tenantKSM.getDefaultPrimaryCertificate();
            }
            if (publicCert != null) {
                publicCerts.put(tenantId, publicCert);
            }
        } else {
            publicCert = publicCerts.get(tenantId);
        }
        return publicCert;
    }

}
