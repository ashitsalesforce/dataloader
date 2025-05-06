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
package com.salesforce.dataloader.client;

import com.salesforce.dataloader.config.AppConfig;
import com.salesforce.dataloader.dyna.ParentIdLookupFieldFormatter;
import com.salesforce.dataloader.dyna.SforceDynaBean;
import com.salesforce.dataloader.process.ProcessTestBase;
import com.sforce.soap.partner.DeleteResult;
import com.sforce.soap.partner.DescribeSObjectResult;
import com.sforce.soap.partner.Field;
import com.sforce.soap.partner.QueryResult;
import com.sforce.soap.partner.SaveResult;
import com.sforce.soap.partner.UpsertResult;
import com.sforce.soap.partner.sobject.SObject;
import com.sforce.ws.ConnectionException;
import org.apache.commons.beanutils.BasicDynaClass;
import org.apache.commons.beanutils.BeanUtils;
import org.apache.commons.beanutils.DynaBean;
import org.apache.commons.beanutils.DynaProperty;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Test for partner client operations provided with dataloader
 * 
 * @author Lexi Viripaeff
 * @author Alex Warshavsky
 * @since 8.0
 */
@SuppressWarnings("unused")
public class PartnerClientTest extends ProcessTestBase {

    @Test
    public void testPartnerClientConnect() throws Exception {
        LoginClient client = LoginClient.getInstance(getController());
        assertFalse(getController().getAppConfig().getBoolean(AppConfig.PROP_SFDC_INTERNAL_IS_SESSION_ID_LOGIN));
        boolean connect = client.connect();
        assertTrue(connect);
        assertNotNull(client.getConnection());
        client.connect(client.getSession());

        PartnerClient partnerClient = getController().getPartnerClient();
        partnerClient.connect(client.getSession());
        assertTrue(partnerClient.getConnection().getDisableFeedTrackingHeader().isDisableFeedTracking());
    }

    @Test
    public void testPartnerClientNoUserName() throws ConnectionException {
        AppConfig appConfig = getController().getAppConfig();
        String origUserName = appConfig.getString(AppConfig.PROP_USERNAME);
        try {
            appConfig.setValue(AppConfig.PROP_USERNAME, "");
            LoginClient client = LoginClient.getInstance(getController());
            boolean connect = client.connect();
            assertFalse("Should not connect with empty username", connect);
        } catch (RuntimeException e) {
            //make sure we get the right error message that mentions the username
            assertTrue(e.getMessage().contains(AppConfig.PROP_USERNAME));
        } finally {
            appConfig.setValue(AppConfig.PROP_USERNAME, origUserName);
        }
    }

    @Test
    public void testPartnerClientSfdcInternalSessionIdConnect() throws Exception {
        AppConfig appConfig = getController().getAppConfig();

        final String origUsername = appConfig.getString(AppConfig.PROP_USERNAME);
        final String origPassword = appConfig.getString(AppConfig.PROP_PASSWORD);
        final String origEndpoint = appConfig.getAuthEndpointForCurrentEnv();

        //login normally just to get sessionId and endpoint
        LoginClient setupOnlyClient = LoginClient.getInstance(getController());
        setupOnlyClient.connect();
        final String sessionId = setupOnlyClient.getSessionId();
        final String endpoint = setupOnlyClient.getSession().getServer();
        setupOnlyClient.disconnect();

        try {
            appConfig.setValue(AppConfig.PROP_USERNAME, "");
            appConfig.setValue(AppConfig.PROP_PASSWORD, "");

            appConfig.setValue(AppConfig.PROP_SFDC_INTERNAL, true);
            appConfig.setValue(AppConfig.PROP_SFDC_INTERNAL_IS_SESSION_ID_LOGIN, true);
            appConfig.setAuthEndpointForCurrentEnv(endpoint);
            appConfig.setValue(AppConfig.PROP_SFDC_INTERNAL_SESSION_ID, sessionId);

            LoginClient client = LoginClient.getInstance(getController());
            assertTrue(client.connect());
        } finally {
            appConfig.setValue(AppConfig.PROP_USERNAME, origUsername);
            appConfig.setValue(AppConfig.PROP_PASSWORD, origPassword);
            appConfig.setAuthEndpointForCurrentEnv(origEndpoint);
            appConfig.setValue(AppConfig.PROP_SFDC_INTERNAL, false);
            appConfig.setValue(AppConfig.PROP_SFDC_INTERNAL_IS_SESSION_ID_LOGIN, false);
            appConfig.setValue(AppConfig.PROP_SFDC_INTERNAL_SESSION_ID, "");
        }
    }

    @Test
    public void testPartnerClientSfdcInternalSessionIdWithoutSfdcInternalConnect() throws Exception {
        AppConfig appConfig = getController().getAppConfig();

        final String origUsername = appConfig.getString(AppConfig.PROP_USERNAME);
        final String origPassword = appConfig.getString(AppConfig.PROP_PASSWORD);
        final String origEndpoint = appConfig.getAuthEndpointForCurrentEnv();

        //login normally just to get sessionId and endpoint
        LoginClient setupOnlyClient = LoginClient.getInstance(getController());
        setupOnlyClient.connect();
        final String sessionId = setupOnlyClient.getSessionId();
        final String endpoint = setupOnlyClient.getSession().getServer();
        setupOnlyClient.disconnect();

        try {
            appConfig.setValue(AppConfig.PROP_USERNAME, "");
            appConfig.setValue(AppConfig.PROP_PASSWORD, "");

            appConfig.setValue(AppConfig.PROP_SFDC_INTERNAL, false);
            appConfig.setValue(AppConfig.PROP_SFDC_INTERNAL_IS_SESSION_ID_LOGIN, true);
            appConfig.setAuthEndpointForCurrentEnv(endpoint);
            appConfig.setValue(AppConfig.PROP_SFDC_INTERNAL_SESSION_ID, sessionId);

            LoginClient client = LoginClient.getInstance(getController());
            client.connect();
            Assert.fail("Should not be able to connect with sfdcInternal=false and no username.");
        } catch (IllegalStateException e) {
            assertEquals(
                    "Wrong error messsage",
                    "Empty salesforce.com username specified.  Please make sure that parameter sfdc.username is set to correct username.",
                    e.getMessage());
        } finally {
            appConfig.setValue(AppConfig.PROP_USERNAME, origUsername);
            appConfig.setValue(AppConfig.PROP_PASSWORD, origPassword);
            appConfig.setAuthEndpointForCurrentEnv(origEndpoint);
            appConfig.setValue(AppConfig.PROP_SFDC_INTERNAL, false);
            appConfig.setValue(AppConfig.PROP_SFDC_INTERNAL_IS_SESSION_ID_LOGIN, false);
            appConfig.setValue(AppConfig.PROP_SFDC_INTERNAL_SESSION_ID, "");
        }
    }

    @Test
    public void testIsSessionValidAlwaysTrueForSessionIdLogin() throws Exception {
        AppConfig appConfig = getController().getAppConfig();

        try {
            appConfig.setValue(AppConfig.PROP_SFDC_INTERNAL, true);
            appConfig.setValue(AppConfig.PROP_SFDC_INTERNAL_IS_SESSION_ID_LOGIN, true);

            LoginClient client = LoginClient.getInstance(getController());
            assertTrue(client.isSessionValid());
        } finally {
            appConfig.setValue(AppConfig.PROP_SFDC_INTERNAL, false);
            appConfig.setValue(AppConfig.PROP_SFDC_INTERNAL_IS_SESSION_ID_LOGIN, false);
        }
    }

    @Test
    public void testDisconnect() throws Exception {
        LoginClient client = LoginClient.getInstance(getController());

        client.connect();
        assertTrue(client.isLoggedIn());

        client.disconnect();
        assertFalse(client.isLoggedIn());
    }

    @Test
    public void testSetEntityDescribe() throws Exception{
    	SObjectMetaDataClient client = SObjectMetaDataClient.getInstance(getController());
        assertNotNull(client.getDescribeGlobalResults());
    }

    @Test
    public void testDescribeSObjects() throws Exception {
        setMemoryIncreaseThresholds(220);
        SObjectMetaDataClient client = SObjectMetaDataClient.getInstance(getController());

        int numDescribes = 0;
        for (String objectType : client.getDescribeGlobalResults().keySet()){
        	try {
        		DescribeSObjectResult describeResult = client.describeSObject(objectType);
        		numDescribes++;
                assertNotNull(describeResult);
                assertEquals(objectType, describeResult.getName());
        	} catch (Exception ex) {
        		if (ex.getMessage().contains("jsonNot")) {
        			System.out.println("PartnerClient.testDescribeSObjects: Unable to call describeSObject for " + objectType);
        		} else {
        			throw ex;

        		}
        	}
        }
    }

    @Test
    public void testSetFieldTypes() throws Exception {
    	SObjectMetaDataClient client = SObjectMetaDataClient.getInstance(getController());
        client.setFieldTypes();
        assertNotNull(client.getFieldTypes());
    }

    @Test
    public void testGetSforceField() throws Exception {
        // test for account name as a default test case
    	SObjectMetaDataClient client = SObjectMetaDataClient.getInstance(getController());
        DescribeSObjectResult forceFields = client.describeSObject("account");
        Field[] fields = forceFields.getFields();
        assertNotNull(fields);
        boolean hasName = false;
        for (Field field : fields) {
            Field f = field;
            if (f.getName().equals("Name")) {
                hasName = true;
            }
        }
        assertTrue("Account Name not found ", hasName);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testInsertBasic() throws Exception {
        // setup our dynabeans
        BasicDynaClass dynaClass;

        Map<String, Object> sforceMapping = new HashMap<String, Object>();
        sforceMapping.put("Name", "name" + System.currentTimeMillis());
        sforceMapping.put("Description", "the description");
        // Account number is set for easier test data cleanup
        sforceMapping.put("AccountNumber", ACCOUNT_NUMBER_PREFIX + System.currentTimeMillis());
        dynaClass = setupDynaClass("Account", (Collection<String>)(Collection<?>)(sforceMapping.values()));
        // now convert to a dynabean array for the client
        DynaBean sforceObj = dynaClass.newInstance();

        // This does an automatic conversion of types.
        BeanUtils.copyProperties(sforceObj, sforceMapping);

        List<DynaBean> beanList = new ArrayList<DynaBean>();
        beanList.add(sforceObj);

        // get the client and make the insert call
        PartnerClient client = PartnerClient.getInstance(getController());
        SaveResult[] results = client.loadInserts(beanList);
        for (SaveResult result : results) {
            if (!result.getSuccess()) {
                Assert.fail("Insert returned an error: " + result.getErrors()[0].getMessage());
            }
        }
    }

    @Test
    public void testUpdateBasic() throws Exception {
        doTestUpdateBasic(false);
    }
    
    @Test
    public void testUpdateBasicWithoutCompression() throws Exception {
        doTestUpdateBasic(true);
    }
        
    @SuppressWarnings("unchecked")
    private void doTestUpdateBasic(boolean noCompression) throws Exception {
        String id = getRandomAccountId();

        // setup our dynabeans
        BasicDynaClass dynaClass;

        Map<String, Object> sforceMapping = new HashMap<String, Object>();
        sforceMapping.put("Id", id);
        sforceMapping.put("Name", "newname" + System.currentTimeMillis());
        sforceMapping.put("Description", "the new description");
        // Account number is set for easier test data cleanup
        sforceMapping.put("AccountNumber", ACCOUNT_NUMBER_PREFIX + System.currentTimeMillis());
        dynaClass = setupDynaClass("Account", (Collection<String>)(Collection<?>)(sforceMapping.values()));

        // now convert to a dynabean array for the client
        DynaBean sforceObj = dynaClass.newInstance();

        // This does an automatic conversion of types.
        BeanUtils.copyProperties(sforceObj, sforceMapping);

        List<DynaBean> beanList = new ArrayList<DynaBean>();
        beanList.add(sforceObj);
        
        getController().getAppConfig().setValue(AppConfig.PROP_NO_COMPRESSION, noCompression);

        // get the client and make the insert call
        PartnerClient client = PartnerClient.getInstance(getController());
        SaveResult[] results = client.loadUpdates(beanList);
        for (SaveResult result : results) {
            if (!result.getSuccess()) {
                Assert.fail("Update returned an error" + result.getErrors()[0].getMessage());
            }
        }
    }

    /**
     * Basic failing - forgetting the id
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testUpdateFailBasic() throws Exception {

        // setup our dynabeans
        BasicDynaClass dynaClass;

        Map<String, Object> sforceMapping = new HashMap<String, Object>();
        sforceMapping.put("Name", "newname" + System.currentTimeMillis());
        sforceMapping.put("Description", "the new description");
        // Account number is set for easier test data cleanup
        sforceMapping.put("AccountNumber", ACCOUNT_NUMBER_PREFIX + System.currentTimeMillis());
        dynaClass = setupDynaClass("Account", (Collection<String>)(Collection<?>)(sforceMapping.values()));

        // now convert to a dynabean array for the client
        DynaBean sforceObj = dynaClass.newInstance();
        // This does an automatic conversion of types.
        BeanUtils.copyProperties(sforceObj, sforceMapping);

        List<DynaBean> beanList = new ArrayList<DynaBean>();
        beanList.add(sforceObj);

        // get the client and make the insert call
        PartnerClient client = PartnerClient.getInstance(getController());
        SaveResult[] results = client.loadUpdates(beanList);
        for (SaveResult result : results) {
            if (result.getSuccess()) {
                Assert.fail("Update should not have been a success.");
            }
        }
    }

    /**
     * Test basic upsert operation
     */
    @Test
    public void testUpsertAccountBasic() throws Exception {
        doUpsertAccount(false);
    }

    /**
     * Test basic upsert operation
     */
    @Test
    public void testUpsertContactBasic() throws Exception {
        doUpsertContact(false);
    }

    /**
     * Test basic upsert on foreign key
     */
    @Test
    public void testUpsertAccountFkBasic() throws Exception {
        doUpsertAccount(true);
    }

    /**
     * Test basic upsert on foreign key
     */
    @Test
    public void testUpsertContactFkBasic() throws Exception {
        doUpsertContact(true);
    }

    /**
     * Test basic failure to upsert - no external id specified
     */
    @Test
    public void testUpsertFailBasic() throws Exception {
        doUpsertFailBasic(false);
    }

    /**
     * Test basic failure to upsert on foreign key - no foreign key external id specified (blank value)
     */
    @Test
    public void testUpsertFkFailBasic() throws Exception {
        doUpsertFailBasic(true);
    }

    private void doUpsertAccount(boolean upsertFk) throws Exception {
        String origExtIdField = getController().getAppConfig().getString(AppConfig.PROP_IDLOOKUP_FIELD);

        try {
            // make sure the external id is set
            String extIdField = setExtIdField(DEFAULT_ACCOUNT_EXT_ID_FIELD);
            Object extIdValue = getRandomExtId("Account", ACCOUNT_WHERE_CLAUSE, null);

            Map<String, Object> sforceMapping = new HashMap<String, Object>();
            sforceMapping.put(extIdField, extIdValue);
            sforceMapping.put("Name", "newname" + System.currentTimeMillis());
            sforceMapping.put("Description", "the new description");
            // Account number is set for easier test data cleanup
            sforceMapping.put("AccountNumber", ACCOUNT_NUMBER_PREFIX + System.currentTimeMillis());

            // Add upsert on FK
            if (upsertFk) {
                Object parentExtIdValue = getRandomExtId("Account", ACCOUNT_WHERE_CLAUSE, extIdValue);
                // if there's only one external id on account, do another upsert and get the second external id thus
                // created
                if (parentExtIdValue == null) {
                    doUpsertAccount(false);
                    parentExtIdValue = getRandomExtId("Account", ACCOUNT_WHERE_CLAUSE, extIdValue);
                }
                sforceMapping.put(new ParentIdLookupFieldFormatter(null, "Parent", extIdField).toString(), parentExtIdValue);
            }

            doUpsert("Account", sforceMapping);
        } finally {
            setExtIdField(origExtIdField);
        }
    }

    private void doUpsertContact(boolean upsertFk) throws Exception {
        String origExtIdField = getController().getAppConfig().getString(AppConfig.PROP_IDLOOKUP_FIELD);

        try {
            // make sure the external id is set
            String extIdField = setExtIdField(DEFAULT_CONTACT_EXT_ID_FIELD);
            Object extIdValue = getRandomExtId("Contact", CONTACT_WHERE_CLAUSE, null);

            Map<String, Object> sforceMapping = new HashMap<String, Object>();
            sforceMapping.put(extIdField, extIdValue);
            sforceMapping.put("FirstName", "newFirstName" + System.currentTimeMillis());
            sforceMapping.put("LastName", "newLastName" + System.currentTimeMillis());
            // Title is set for easier test data cleanup
            sforceMapping.put("Title", CONTACT_TITLE_PREFIX + System.currentTimeMillis());

            // Add upsert on FK -- reference to an account
            if (upsertFk) {
                // remember original ext id field
                String oldExtIdField = getController().getAppConfig().getString(AppConfig.PROP_IDLOOKUP_FIELD);

                String acctExtIdField = setExtIdField(DEFAULT_ACCOUNT_EXT_ID_FIELD);
                Object accountExtIdValue = getRandomExtId("Account", ACCOUNT_WHERE_CLAUSE, null);
                // if there's only one external id on account, do another upsert and get the second external id thus
                // created
                if (accountExtIdValue == null) {
                    doUpsertAccount(false);
                    accountExtIdValue = getRandomExtId("Account", ACCOUNT_WHERE_CLAUSE, accountExtIdValue);
                }
                sforceMapping.put(new ParentIdLookupFieldFormatter(null, "Account", acctExtIdField).toString(), accountExtIdValue);

                // restore ext id field
                setExtIdField(oldExtIdField);
            }

            doUpsert("Contact", sforceMapping);

        } finally {
            setExtIdField(origExtIdField);
        }
    }

    /**
     * Basic failing - forgetting the external id or foreign key external id
     */
    @SuppressWarnings("unchecked")
    private void doUpsertFailBasic(boolean upsertFk) throws Exception {

        // setup our dynabeans
        BasicDynaClass dynaClass;

        Map<String, Object> sforceMapping = new HashMap<String, Object>();
        sforceMapping.put("Name", "newname" + System.currentTimeMillis());
        sforceMapping.put("Description", "the new description");
        // Account number is set for easier test data cleanup
        sforceMapping.put("AccountNumber", ACCOUNT_NUMBER_PREFIX + System.currentTimeMillis());

        // Add FAILURE for upsert on FK.
        String extIdField = setExtIdField(DEFAULT_ACCOUNT_EXT_ID_FIELD);
        Object extIdValue = getRandomExtId("Account", ACCOUNT_WHERE_CLAUSE, null);
        if (upsertFk) {
            sforceMapping.put(extIdField, extIdValue);
            // forget to set the foreign key external id value
            sforceMapping.put(new ParentIdLookupFieldFormatter(null, "Parent", extIdField).toString(), "bogus");
        }
        dynaClass = setupDynaClass("Account", (Collection<String>)(Collection<?>)(sforceMapping.values()));

        // now convert to a dynabean array for the client
        DynaBean sforceObj = dynaClass.newInstance();

        // This does an automatic conversion of types.
        BeanUtils.copyProperties(sforceObj, sforceMapping);

        List<DynaBean> beanList = new ArrayList<DynaBean>();
        beanList.add(sforceObj);

        PartnerClient client = PartnerClient.getInstance(getController());
        UpsertResult[] results = client.loadUpserts(beanList);
        for (UpsertResult result : results) {
            if (result.getSuccess()) {
                Assert.fail("Upsert should not have been a success.");
            }
        }
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testDeleteBasic() throws Exception {
        String id = getRandomAccountId();

        // setup our dynabeans
        BasicDynaClass dynaClass;

        Map<String, Object> sforceMapping = new HashMap<String, Object>();
        sforceMapping.put("Id", id);
        sforceMapping.put("Name", "name" + System.currentTimeMillis());
        sforceMapping.put("Description", "the description");
        // Account number is set for easier test data cleanup
        sforceMapping.put("AccountNumber", ACCOUNT_NUMBER_PREFIX + System.currentTimeMillis());
        dynaClass = setupDynaClass("Account", (Collection<String>)(Collection<?>)(sforceMapping.values()));

        // now convert to a dynabean array for the client
        DynaBean sforceObj = dynaClass.newInstance();

        // This does an automatic conversion of types.
        BeanUtils.copyProperties(sforceObj, sforceMapping);

        List<DynaBean> beanList = new ArrayList<DynaBean>();
        beanList.add(sforceObj);

        // get the client and make the insert call
        PartnerClient client = PartnerClient.getInstance(getController());
        DeleteResult[] results = client.loadDeletes(beanList);
        for (DeleteResult result : results) {
            if (!result.getSuccess()) {
                Assert.fail("Delete returned an error: " + result.getErrors()[0].getMessage());
            }
        }
    }

    /**
     * Test a delete missing the id
     */
    @Test
    public void testDeleteFailBasic() throws Exception {

        // setup our dynabeans
        BasicDynaClass dynaClass;

        Map<String, Object> sforceMapping = new HashMap<String, Object>();
        sforceMapping.put("name", "name" + System.currentTimeMillis());
        sforceMapping.put("description", "the description");
        // Account number is set for easier test data cleanup
        sforceMapping.put("AccountNumber", ACCOUNT_NUMBER_PREFIX + System.currentTimeMillis());
        dynaClass = setupDynaClass("Account", (Collection<String>)(Collection<?>)(sforceMapping.values()));

        // now convert to a dynabean array for the client
        DynaBean sforceObj = dynaClass.newInstance();

        // This does an automatic conversion of types.
        BeanUtils.copyProperties(sforceObj, sforceMapping);

        List<DynaBean> beanList = new ArrayList<DynaBean>();
        beanList.add(sforceObj);

        // get the client and make the insert call
        PartnerClient client = PartnerClient.getInstance(getController());
        DeleteResult[] results = client.loadDeletes(beanList);
        for (DeleteResult result : results) {
            if (result.getSuccess()) {
                Assert.fail("Delete should have returned an error");
            }
        }
    }

    @Test
    public void testQueryBasic() throws Exception {
        // make sure there're some records to test with
        upsertSfdcAccounts(10);

        // get the client and make the query call
        PartnerClient client = PartnerClient.getInstance(getController());
        QueryResult result = client.query("select id from account where " + ACCOUNT_WHERE_CLAUSE);
        SObject[] records = result.getRecords();
        assertNotNull(records);
        assertTrue(records.length > 0);

        // test query more if we have more records
        if (!result.getDone()) {
            QueryResult result2 = client.queryMore(result.getQueryLocator());

            // if we are not done, we should get some records back
            assertNotNull(result2.getRecords());
            assertTrue(records.length > 0);
        }
    }

    /**
     * Get a random acount id for delete and update testing
     * 
     * @return String account id
     */
    private String getRandomAccountId() throws ConnectionException {
        // make sure there're some records to get
        upsertSfdcAccounts(10);

        // get the client and make the query call
        PartnerClient client = PartnerClient.getInstance(getController());
        QueryResult result = client.query("select id from account where " + ACCOUNT_WHERE_CLAUSE);
        SObject[] records = result.getRecords();
        assertNotNull(records);
        assertTrue(records.length > 0);

        return records[0].getId();
    }
}
