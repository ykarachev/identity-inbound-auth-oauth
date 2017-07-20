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

import junit.framework.TestCase;
import org.apache.commons.codec.binary.Hex;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.KeyProviderService;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import sun.security.x509.X509CertImpl;

import java.lang.reflect.Method;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

/**
 * Tests for certificate store, with extension mechanism works.
 */
public class CertificatesStoreTest extends TestCase {

    public void setUp() throws Exception {
        KeyProviderService mockKeyProvider = new KeyProviderService() {

            @Override
            public PrivateKey getPrivateKey(String tenantDomain) throws IdentityException {
                return null;
            }

            @Override
            public Certificate getCertificate(String tenantDomain) throws IdentityException {
                try {
                    return new X509CertImpl(
                            CertificatesStoreTest.class.getResourceAsStream("512b-rsa-example-cert.pem"));
                } catch (CertificateException e) {
                    throw new IdentityException("Could not load test certificate", e);
                }
            }
        };
        Method m = OAuth2ServiceComponentHolder.class.getDeclaredMethod("setKeyProvider", KeyProviderService.class);
        m.setAccessible(true);
        m.invoke(null, mockKeyProvider);
    }

    public void testGetCertificate() throws Exception {

        CertificatesStore certificatesStore = new CertificatesStore();
        Certificate certificate = certificatesStore.getCertificate("test.domain", 2);
        assertNotNull(certificate);
    }

    public void testGetThumbPrint() throws Exception {
        CertificatesStore certificatesStore = new CertificatesStore();
        String thumb = certificatesStore.getThumbPrint("test.domain", 2);
        assertNotNull(thumb);
    }

    /**
     * Verifies that the previous method which is similar to   private String hexify(byte bytes[]) retruns the
     * same result as the one provided by commons-codec.
     */
    public void testHexify() {
        byte[] test1 = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
        String test1AsStr = "000102030405060708090a0b0c0d0e0f";
        String s1 = Hex.encodeHexString(test1);
        String s2 = hexify(test1);
        assertEquals(s1, s2);
        assertEquals(test1AsStr, s2);
    }

    /**
     * Helper method to hexify a byte array.
     * TODO:need to verify the logic
     *
     * @param bytes
     * @return hexadecimal representation
     */
    private String hexify(byte bytes[]) {

        char[] hexDigits = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

        StringBuilder buf = new StringBuilder(bytes.length * 2);

        for (int i = 0; i < bytes.length; ++i) {
            buf.append(hexDigits[(bytes[i] & 0xf0) >> 4]);
            buf.append(hexDigits[bytes[i] & 0x0f]);
        }

        return buf.toString();
    }
}