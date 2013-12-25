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

import javax.annotation.Generated;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for anonymous complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType>
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="minor" type="{http://www.w3.org/2001/XMLSchema}short"/>
 *         &lt;element name="major" type="{http://www.w3.org/2001/XMLSchema}short"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
    "minor",
    "major"
})
@XmlRootElement(name = "faultDetail")
@Generated(value = "com.sun.tools.xjc.Driver", date = "2013-01-28T07:05:22-05:00", comments = "JAXB RI vhudson-jaxb-ri-2.1-2")
public class FaultDetail {

    @Generated(value = "com.sun.tools.xjc.Driver", date = "2013-01-28T07:05:22-05:00", comments = "JAXB RI vhudson-jaxb-ri-2.1-2")
    protected short minor;
    @Generated(value = "com.sun.tools.xjc.Driver", date = "2013-01-28T07:05:22-05:00", comments = "JAXB RI vhudson-jaxb-ri-2.1-2")
    protected short major;

    /**
     * Gets the value of the minor property.
     * 
     */
    @Generated(value = "com.sun.tools.xjc.Driver", date = "2013-01-28T07:05:22-05:00", comments = "JAXB RI vhudson-jaxb-ri-2.1-2")
    public short getMinor() {
        return minor;
    }

    /**
     * Sets the value of the minor property.
     * 
     */
    @Generated(value = "com.sun.tools.xjc.Driver", date = "2013-01-28T07:05:22-05:00", comments = "JAXB RI vhudson-jaxb-ri-2.1-2")
    public void setMinor(short value) {
        this.minor = value;
    }

    /**
     * Gets the value of the major property.
     * 
     */
    @Generated(value = "com.sun.tools.xjc.Driver", date = "2013-01-28T07:05:22-05:00", comments = "JAXB RI vhudson-jaxb-ri-2.1-2")
    public short getMajor() {
        return major;
    }

    /**
     * Sets the value of the major property.
     * 
     */
    @Generated(value = "com.sun.tools.xjc.Driver", date = "2013-01-28T07:05:22-05:00", comments = "JAXB RI vhudson-jaxb-ri-2.1-2")
    public void setMajor(short value) {
        this.major = value;
    }

}
