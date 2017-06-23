package org.wso2.carbon.identity.oauth.scope.endpoint;

import org.wso2.carbon.identity.oauth.scope.endpoint.dto.*;
import org.wso2.carbon.identity.oauth.scope.endpoint.ScopesApiService;
import org.wso2.carbon.identity.oauth.scope.endpoint.factories.ScopesApiServiceFactory;

import io.swagger.annotations.ApiParam;

import org.wso2.carbon.identity.oauth.scope.endpoint.dto.ErrorDTO;
import org.wso2.carbon.identity.oauth.scope.endpoint.dto.ScopeDTO;

import java.util.List;

import java.io.InputStream;
import org.apache.cxf.jaxrs.ext.multipart.Attachment;
import org.apache.cxf.jaxrs.ext.multipart.Multipart;

import javax.ws.rs.core.Response;
import javax.ws.rs.*;

@Path("/scopes")
@Consumes({ "application/json" })
@Produces({ "application/json" })
@io.swagger.annotations.Api(value = "/scopes", description = "the scopes API")
public class ScopesApi  {

   private final ScopesApiService delegate = ScopesApiServiceFactory.getScopesApi();

    @DELETE
    @Path("/{id}")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @io.swagger.annotations.ApiOperation(value = "Delete Scope\n", notes = "This API is used to delete scope by scope ID.\n", response = String.class)
    @io.swagger.annotations.ApiResponses(value = { 
        @io.swagger.annotations.ApiResponse(code = 204, message = "Successful deleted"),
        
        @io.swagger.annotations.ApiResponse(code = 500, message = "Server Error") })

    public Response deleteScopeByID(@ApiParam(value = "scope ID of the scope which need to get deleted",required=true ) @PathParam("id") String id)
    {
    return delegate.deleteScopeByID(id);
    }
    @GET
    @Path("/{id}")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @io.swagger.annotations.ApiOperation(value = "Get a Scope by Scope ID\n", notes = "This API is used to get a scope by given scope ID.\n", response = ScopeDTO.class)
    @io.swagger.annotations.ApiResponses(value = { 
        @io.swagger.annotations.ApiResponse(code = 200, message = "Successful Retrieved"),
        
        @io.swagger.annotations.ApiResponse(code = 404, message = "Not Found"),
        
        @io.swagger.annotations.ApiResponse(code = 500, message = "Server Error") })

    public Response getScopeByID(@ApiParam(value = "scope id of the scope which the details to be retrieved",required=true ) @PathParam("id") String id)
    {
    return delegate.getScopeByID(id);
    }
    @GET
    
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @io.swagger.annotations.ApiOperation(value = "Get all available Scopes\n", notes = "This API is used to get all the available scopes.\n", response = ScopeDTO.class, responseContainer = "List")
    @io.swagger.annotations.ApiResponses(value = { 
        @io.swagger.annotations.ApiResponse(code = 200, message = "Successful Retrieved"),
        
        @io.swagger.annotations.ApiResponse(code = 404, message = "Not Found"),
        
        @io.swagger.annotations.ApiResponse(code = 500, message = "Server Error") })

    public Response getScopes(@ApiParam(value = "filter when retrieving all available scopes") @QueryParam("filter") String filter,
    @ApiParam(value = "start index of the list of scopes to be retrieved") @QueryParam("startIndex") Integer startIndex,
    @ApiParam(value = "a limited number of scopes to be retrieved") @QueryParam("count") Integer count,
    @ApiParam(value = "parameter which based on sorting and retrieving available scopes") @QueryParam("sortBy") String sortBy,
    @ApiParam(value = "sorting order used when sorting and retrieving available scopes") @QueryParam("sortOrder") String sortOrder)
    {
    return delegate.getScopes(filter,startIndex,count,sortBy,sortOrder);
    }
    @HEAD
    @Path("/names/{name}")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @io.swagger.annotations.ApiOperation(value = "Check Scope Existance using Scope Name\n", notes = "This API is used to check scope existance using scope name.\n", response = String.class)
    @io.swagger.annotations.ApiResponses(value = { 
        @io.swagger.annotations.ApiResponse(code = 200, message = "Scope Exists"),
        
        @io.swagger.annotations.ApiResponse(code = 404, message = "Not Found"),
        
        @io.swagger.annotations.ApiResponse(code = 500, message = "Server Error") })

    public Response isScopeExists(@ApiParam(value = "scope name of the scope which the existance should be checked",required=true ) @PathParam("name") String name)
    {
    return delegate.isScopeExists(name);
    }
    @POST
    
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @io.swagger.annotations.ApiOperation(value = "Register a Scope\n", notes = "This API is used to create a scope.\n", response = ScopeDTO.class)
    @io.swagger.annotations.ApiResponses(value = { 
        @io.swagger.annotations.ApiResponse(code = 201, message = "Successful created"),
        
        @io.swagger.annotations.ApiResponse(code = 400, message = "Bad Request"),
        
        @io.swagger.annotations.ApiResponse(code = 409, message = "Conflict"),
        
        @io.swagger.annotations.ApiResponse(code = 500, message = "Server Error") })

    public Response registerScope(@ApiParam(value = "a scope with the bindings which to be registered" ,required=true ) ScopeDTO scope)
    {
    return delegate.registerScope(scope);
    }
    @PUT
    @Path("/{id}")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @io.swagger.annotations.ApiOperation(value = "Update a Scope\n", notes = "This API is used to update a scope by scope ID.\n", response = String.class)
    @io.swagger.annotations.ApiResponses(value = { 
        @io.swagger.annotations.ApiResponse(code = 200, message = "Successful updated"),
        
        @io.swagger.annotations.ApiResponse(code = 409, message = "Conflict"),
        
        @io.swagger.annotations.ApiResponse(code = 500, message = "Server Error") })

    public Response updateScopeByID(@ApiParam(value = "updated scope" ,required=true ) ScopeDTO scope,
    @ApiParam(value = "scope ID of the scope which need to get updated",required=true ) @PathParam("id") String id)
    {
    return delegate.updateScopeByID(scope,id);
    }
}

