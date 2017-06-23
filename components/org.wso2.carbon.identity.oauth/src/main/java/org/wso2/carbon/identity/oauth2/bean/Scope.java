/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.oauth2.bean;

import java.io.Serializable;
import java.util.List;

public class Scope implements Serializable {

    /**
     * Required
     **/
    String id;

    /**
     * Required
     **/
    String name;

    /**
     * Required
     **/
    String description;

    /**
     * Optional
     **/
    List<String> bindings;

    public Scope() {

    }

    public Scope(String name, String description, List<String> bindings) {
        this.name = name;
        this.description = description;
        this.bindings = bindings;
    }

    public Scope(String id, String name, String description, List<String> bindings) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.bindings = bindings;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<String> getBindings() {
        return bindings;
    }

    public void setBindings(List<String> bindings) {
        this.bindings = bindings;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}

