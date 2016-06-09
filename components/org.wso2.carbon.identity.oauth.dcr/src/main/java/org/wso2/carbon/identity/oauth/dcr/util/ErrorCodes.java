package org.wso2.carbon.identity.oauth.dcr.util;


public enum ErrorCodes {
    META_DATA_VALIDATION_FAILED("Requested meta data will not be satisfied as in the specification.");

    private String description ;
    ErrorCodes(String description) {
        this.description = description ;
    }
    public String getDescription(){
        return this.description ;
    }
}
