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

package org.wso2.carbon.identity.oidc;

import org.wso2.carbon.identity.oauth2poc.bean.context.OAuth2MessageContext;

import java.util.HashSet;
import java.util.Set;

public class IDTokenBuilder {

    protected OAuth2MessageContext messageContext;

    private String iss;

    private String sub;

    private Set<String> aud = new HashSet<>();

    private String exp;

    private String iat;

    private String authTime;

    private String nonce;

    private String acr;

    private Set<String> amr = new HashSet<>();

    private String azp;

    private String atHash;

    private String cHash;

    public IDTokenBuilder(OAuth2MessageContext messageContext) {
        this.messageContext = messageContext;
    }

    // May need to build IDToken from other service endpoints
    public IDTokenBuilder() {

    }

    public IDTokenBuilder setIss(String iss) {
        this.iss = iss;
        return this;
    }

    public IDTokenBuilder setSub(String sub) {
        this.sub = sub;
        return this;
    }

    public IDTokenBuilder setAud(Set<String> aud) {
        this.aud = aud;
        return this;
    }

    public IDTokenBuilder addAud(String aud) {
        this.aud.add(aud);
        return this;
    }

    public IDTokenBuilder setExp(String exp) {
        this.exp = exp;
        return this;
    }

    public IDTokenBuilder setIat(String iat) {
        this.iat = iat;
        return this;
    }

    public IDTokenBuilder setAuthTime(String authTime) {
        this.authTime = authTime;
        return this;
    }

    public IDTokenBuilder setNonce(String nonce) {
        this.nonce = nonce;
        return this;
    }

    public IDTokenBuilder setACR(String acr) {
        this.acr = acr;
        return this;
    }

    public IDTokenBuilder setAMR(Set<String> amr) {
        this.amr = amr;
        return this;
    }

    public IDTokenBuilder addAMR(String amr) {
        this.amr.add(amr);
        return this;
    }

    public IDTokenBuilder setAZP(String azp) {
        this.azp = azp;
        return this;
    }

    public IDTokenBuilder setAtHash(String atHash) {
        this.atHash = atHash;
        return this;
    }

    public IDTokenBuilder setCHash(String cHash) {
        this.cHash = cHash;
        return this;
    }

    public String build() {
        // use nimbus to build the IDToken;
        return null;
    }
}
