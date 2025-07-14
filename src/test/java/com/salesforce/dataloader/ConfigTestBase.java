/*
 * Copyright (c) 2015, salesforce.com, inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *    Redistributions of source code must retain the above copyright notice, this list of conditions and the
 *    following disclaimer.
 *
 *    Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
 *    the following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 *    Neither the name of salesforce.com, inc. nor the names of its contributors may be used to endorse or
 *    promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package com.salesforce.dataloader;

import com.salesforce.dataloader.config.AppConfig;

import org.junit.Before;

import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;

public abstract class ConfigTestBase extends TestBase {

    /** Each enum represents a property that we read from test.properties and use as dataloader config settings. */
    @Deprecated
    protected static enum TestProperties {
        @Deprecated
        ENTITY_DEFAULT(AppConfig.PROP_ENTITY), @Deprecated
        ACCOUNT_EXTID(AppConfig.PROP_IDLOOKUP_FIELD);

        private final String configName;

        TestProperties(String configName) {
            this.configName = configName;
        }

        /**
         * Translates the enum name into a property name found in test.properties.
         *
         * @return A property name in the test.properties file. EG USER_ADMIN becomes "test.user.admin"
         */
        private String getPropertyName() {
            return "test." + name().toLowerCase().replace('_', '.');
        }

        public void putConfigSetting(Map<String, String> destConfig) {
            destConfig.put(this.configName, getProperty(getPropertyName()));
        }
    }

    private final Map<String, String> baseConfig;

    protected Map<String, String> getTestConfig() {
        final HashMap<String, String> configBase = new HashMap<String, String>(this.baseConfig);
        configBase.put(AppConfig.PROP_LAST_RUN_OUTPUT_DIR, getTestStatusDir());
        for (TestProperties prop : getDefaultTestPropertiesSet()) {
            prop.putConfigSetting(configBase);
        }
        for (Entry<Object, Object> prop : getTestBaseProperties().entrySet()) {
            configBase.put(prop.getKey().toString(), prop.getValue().toString());
        }
        configBase.put(AppConfig.CLI_OPTION_CONFIG_DIR_PROP, TEST_CONF_DIR);
        String proxyUsername = System.getProperty(AppConfig.PROP_PROXY_USERNAME);
        String proxyPassword = System.getProperty(AppConfig.PROP_PROXY_PASSWORD);
        if (proxyUsername != null && proxyPassword != null) {
            configBase.put(AppConfig.PROP_PROXY_USERNAME, proxyUsername);
            configBase.put(AppConfig.PROP_PROXY_PASSWORD, proxyPassword);
        }
        return configBase;
    }

    protected Set<TestProperties> getDefaultTestPropertiesSet() {
        Set<TestProperties> propSet = EnumSet.noneOf(TestProperties.class);
        propSet.add(TestProperties.ENTITY_DEFAULT);
        propSet.add(TestProperties.ACCOUNT_EXTID);
        return propSet;
    }

    protected ConfigTestBase() {
        this(Collections.<String, String>emptyMap());
    }

    protected ConfigTestBase(Map<String, String> testConfig) {
        if (testConfig == null) {
            testConfig = new HashMap<String, String>();
        }
        this.baseConfig = testConfig;
    }

    protected String getPKCEClientId() {
        String id = getProperty("test.clientid.pkce");
        if (id != null && !id.isEmpty()) return id;
        return getProperty("test.clientid"); // fallback
    }
    protected String getServerClientId() {
        String id = getProperty("test.clientid.server");
        if (id != null && !id.isEmpty()) return id;
        return getProperty("test.clientid"); // fallback
    }
    protected String getDeviceClientId() {
        String id = getProperty("test.clientid.device");
        if (id != null && !id.isEmpty()) return id;
        return getProperty("test.clientid"); // fallback
    }

    @Before
    public void setupController() throws Exception {
        super.setupController(getTestConfig());
    }
}
