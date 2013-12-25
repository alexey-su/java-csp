/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.company.security.csp.wss4j.test.hello_world_soap_http;

import javax.xml.ws.WebFault;


/**
 * This class was generated by Apache CXF 2.7.3
 * 2013-02-28T10:12:10.652Z
 * Generated source version: 2.7.3
 */

@WebFault(name = "faultDetail", targetNamespace = "http://apache.org/hello_world_soap_http/types")
public class PingMeFault extends Exception {
    private static final long serialVersionUID = -8313446712127506030L;

    private FaultDetail faultDetail;

    public PingMeFault() {
        super();
    }

    public PingMeFault(String message) {
        super(message);
    }

    public PingMeFault(String message, Throwable cause) {
        super(message, cause);
    }

    public PingMeFault(String message, FaultDetail faultDetail) {
        super(message);
        this.faultDetail = faultDetail;
    }

    public PingMeFault(String message, FaultDetail faultDetail, Throwable cause) {
        super(message, cause);
        this.faultDetail = faultDetail;
    }

    public FaultDetail getFaultInfo() {
        return this.faultDetail;
    }
}
