package org.wso2.carbon.identity.oauth.config;

import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import java.util.Properties;

import static org.testng.Assert.*;

public class OAuthCallbackHandlerMetaDataTest {
    OAuthCallbackHandlerMetaData oAuthCallbackHandlerMetaData;

    @Test
    public void testGetPriority() throws Exception {
        Assert.assertEquals(oAuthCallbackHandlerMetaData.getPriority(), 1);
    }

    @Test
    public void testGetProperties() throws Exception {
        Properties assertProperty = oAuthCallbackHandlerMetaData.getProperties();
        Assert.assertEquals(assertProperty.getProperty("property1"), "propertyValue");
    }

    @Test
    public void testGetClassName() throws Exception {
        assertEquals(oAuthCallbackHandlerMetaData.getClassName(), "testClass");
    }

    @BeforeTest
    public void setUp() throws Exception {
        Properties properties = new Properties();
        properties.setProperty("property1", "propertyValue");
        oAuthCallbackHandlerMetaData = new OAuthCallbackHandlerMetaData("testClass", properties, 1);
    }
}
