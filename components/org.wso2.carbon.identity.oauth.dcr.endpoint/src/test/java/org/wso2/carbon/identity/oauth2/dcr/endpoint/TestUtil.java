package org.wso2.carbon.identity.oauth2.dcr.endpoint;

import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth.dcr.service.DCRMService;


/**
 * Created by hasini on 10/13/17.
 */
public class TestUtil{
    public static void startTenantFlow (String tenantDomain) {
        String carbonHome = TestUtil.class.getResource("/").getFile();
        System.setProperty("carbon.home", carbonHome);
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain);
//        PrivilegedCarbonContext.getThreadLocalCarbonContext().getOSGiService(DCRMService.class,null);
    }
}
