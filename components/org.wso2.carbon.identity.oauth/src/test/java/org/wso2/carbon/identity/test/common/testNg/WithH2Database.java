package org.wso2.carbon.identity.test.common.testNg;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface WithH2Database {
    String jndiName();
    String dbName() default "test";
    String[] files();
}
