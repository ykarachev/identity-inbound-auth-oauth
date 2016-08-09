package org.wso2.carbon.identity.oauth2.listener;

import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.stratos.common.beans.TenantInfoBean;
import org.wso2.carbon.stratos.common.exception.StratosException;
import org.wso2.carbon.stratos.common.listeners.TenantMgtListener;

/**
 * This is an implementation of TenantMgtListener. This uses
 * to generate OIDC scopes in registry
 */

public class TenantCreationEventListener implements TenantMgtListener {
    @Override
    public void onTenantCreate(TenantInfoBean tenantInfoBean) throws StratosException {
        int tenantId = tenantInfoBean.getTenantId();
        OAuth2Util.initiateOIDCScopes(tenantId);
    }

    @Override
    public void onTenantUpdate(TenantInfoBean tenantInfoBean) throws StratosException {

    }

    @Override
    public void onTenantDelete(int i) {

    }

    @Override
    public void onTenantRename(int i, String s, String s1) throws StratosException {

    }

    @Override
    public void onTenantInitialActivation(int i) throws StratosException {

    }

    @Override
    public void onTenantActivation(int i) throws StratosException {

    }

    @Override
    public void onTenantDeactivation(int i) throws StratosException {

    }

    @Override
    public void onSubscriptionPlanChange(int i, String s, String s1) throws StratosException {

    }

    @Override
    public int getListenerOrder() {
        return 0;
    }

    @Override
    public void onPreDelete(int i) throws StratosException {

    }
}
