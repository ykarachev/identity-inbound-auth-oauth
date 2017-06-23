package org.wso2.carbon.identity.oauth.scope.endpoint;

import org.wso2.carbon.identity.oauth.scope.endpoint.*;
import org.wso2.carbon.identity.oauth.scope.endpoint.dto.*;

import org.wso2.carbon.identity.oauth.scope.endpoint.dto.ErrorDTO;
import org.wso2.carbon.identity.oauth.scope.endpoint.dto.ScopeDTO;

import java.util.List;

import java.io.InputStream;
import org.apache.cxf.jaxrs.ext.multipart.Attachment;

import javax.ws.rs.core.Response;

public abstract class ScopesApiService {
    public abstract Response deleteScopeByID(String id);
    public abstract Response getScopeByID(String id);
    public abstract Response getScopes(String filter,Integer startIndex,Integer count,String sortBy,String sortOrder);
    public abstract Response isScopeExists(String name);
    public abstract Response registerScope(ScopeDTO scope);
    public abstract Response updateScopeByID(ScopeDTO scope,String id);
}

