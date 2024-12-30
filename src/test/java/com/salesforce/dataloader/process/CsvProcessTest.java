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

package com.salesforce.dataloader.process;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.salesforce.dataloader.TestSetting;
import com.salesforce.dataloader.TestVariant;
import com.salesforce.dataloader.action.OperationInfo;
import com.salesforce.dataloader.config.AppConfig;
import com.salesforce.dataloader.controller.Controller;
import com.salesforce.dataloader.dao.csv.CSVFileReader;
import com.salesforce.dataloader.dyna.DateTimeConverter;
import com.salesforce.dataloader.exception.DataAccessObjectException;
import com.salesforce.dataloader.exception.ProcessInitializationException;
import com.salesforce.dataloader.model.Row;
import com.salesforce.dataloader.model.TableRow;
import com.salesforce.dataloader.util.AppUtil;
import com.sforce.soap.partner.sobject.SObject;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Test for dataloader batch interface, also known as "integration framework"
 *
 * @author Alex Warshavsky
 * @since 8.0
 * @hierarchy API.dataloader Csv Process Tests
 * @userstory Commenting existing data loader tests and uploading into QA force
 */
@RunWith(Parameterized.class)
@SuppressWarnings("unused")
public class CsvProcessTest extends ProcessTestBase {
    private static long startTime = 0;
    @BeforeClass
    public static void setUpBeforeClass() {
        startTime = System.currentTimeMillis();
    }

    @AfterClass
    public static void tearDownAfterClass() {
        long endTime = System.currentTimeMillis();
        long elapsedTimeInMinutes = (endTime - startTime) / 60000;
        assertTrue("Tests slowed down by more than 1 minute", elapsedTimeInMinutes < 15);
    }
    
    public CsvProcessTest(Map<String, String> config) {
        super(config);
    }

    @Parameterized.Parameters(name = "{0}")
    public static Collection<Object[]> getParameters() {
        return Arrays.asList(
                TestVariant.defaultSettings(),
                TestVariant.forSettings(TestSetting.COMPOSITE_REST_API_ENABLED),
                TestVariant.forSettings(TestSetting.BULK_API_ENABLED),
                TestVariant.forSettings(TestSetting.BULK_API_ENABLED, TestSetting.COMPRESSION_DISABLED),
                TestVariant.forSettings(TestSetting.BULK_API_ENABLED, TestSetting.BULK_API_CACHE_DAO_UPLOAD_ENABLED),
                TestVariant.forSettings(TestSetting.BULK_API_ENABLED, TestSetting.BULK_API_SERIAL_MODE_ENABLED),
                TestVariant.forSettings(TestSetting.BULK_API_ENABLED, TestSetting.BULK_API_ZIP_CONTENT_ENABLED),
                TestVariant.forSettings(TestSetting.BULK_API_ENABLED, TestSetting.BULK_V2_API_ENABLED)
                );
    }

    /**
     * Tests the insert operation on Account - Positive test.
     */
    @Test
    public void testInsertAccountCsv() throws Exception {
        Map<String, String> configMap = getTestConfig(OperationInfo.insert, false);
        if (isSettingEnabled(configMap, AppConfig.PROP_BULK_API_ZIP_CONTENT)
                || isSettingEnabled(configMap, AppConfig.PROP_PROCESS_BULK_CACHE_DATA_FROM_DAO)
                || isSettingEnabled(configMap, AppConfig.PROP_BULK_API_SERIAL_MODE)
                || isSettingEnabled(configMap, AppConfig.PROP_NO_COMPRESSION)
                ) {
            return;
        }
        runProcess(configMap, 100);
    }
    
    @Test
    public void testInsertAccountWithMultipleBatchesCSV() throws ProcessInitializationException, DataAccessObjectException {
        Map<String, String> configMap = getTestConfig(OperationInfo.insert, false);
        if (isSettingEnabled(configMap, AppConfig.PROP_BULK_API_ZIP_CONTENT)
                || isSettingEnabled(configMap, AppConfig.PROP_UPDATE_WITH_EXTERNALID)
                || isSettingEnabled(configMap, AppConfig.PROP_BULK_API_SERIAL_MODE)
                || isSettingEnabled(configMap, AppConfig.PROP_NO_COMPRESSION)
                ) {
            return;
        }
        configMap.put(AppConfig.PROP_IMPORT_BATCH_SIZE, "1");
        Controller controller = runProcessWithErrors(configMap, 2, 1);
        String successFileName = controller.getAppConfig().getString(AppConfig.PROP_OUTPUT_SUCCESS);
        File successFile = new File(successFileName);
        CSVFileReader csvReader = new CSVFileReader(successFile, controller.getAppConfig(), false, false);
        TableRow row1 = csvReader.readTableRow();
        TableRow row2 = csvReader.readTableRow();
        String oracleIdRow1 = (String)row1.get("oracle_id");
        String oracleIdRow2 = (String)row2.get("oracle_id");
        if (oracleIdRow1 == null) {
            oracleIdRow1 = (String)row1.get("oracle_id__c");
            oracleIdRow2 = (String)row2.get("oracle_id__c");
        }
        assertTrue("incorrect success row 1", oracleIdRow1.equals("o1"));
        assertTrue("incorrect success row 2, expected oracle_id = o3", oracleIdRow2.equals("o3"));
    }

    /**
     * Tests the insert operation on Account - Positive test.
     */
    @Test
    public void testInsertTaskWithContactAsWhoCsv() throws Exception {
        Map<String, String> configMap = getTestConfig(OperationInfo.insert, false);
        if (isSettingEnabled(configMap, AppConfig.PROP_BULK_API_ZIP_CONTENT)
                || isSettingEnabled(configMap, AppConfig.PROP_UPDATE_WITH_EXTERNALID)
                || isSettingEnabled(configMap, AppConfig.PROP_PROCESS_BULK_CACHE_DATA_FROM_DAO)
                || isSettingEnabled(configMap, AppConfig.PROP_BULK_API_SERIAL_MODE)
                || isSettingEnabled(configMap, AppConfig.PROP_NO_COMPRESSION)
                ) {
            return;
        }
        Map<String, Object> sforceMapping = new HashMap<String, Object>();
        sforceMapping.put("Email", "contactFor@PolymorphicMappingOfTask.com");
        sforceMapping.put("Subject", "Contact to test Polymorphic mapping of Who relationship on Task");
        sforceMapping.put("FirstName", "newFirstName" + System.currentTimeMillis());
        sforceMapping.put("LastName", "newLastName" + System.currentTimeMillis());
        // Title is set for easier test data cleanup
        sforceMapping.put("Title", CONTACT_TITLE_PREFIX + System.currentTimeMillis());

        String extIdField = setExtIdField(DEFAULT_CONTACT_EXT_ID_FIELD);
        Object extIdValue = getRandomExtId("Contact", CONTACT_WHERE_CLAUSE, null);
        sforceMapping.put(extIdField, extIdValue);

        String oldExtIdField = getController().getAppConfig().getString(AppConfig.PROP_IDLOOKUP_FIELD);
        setExtIdField(extIdField);
        doUpsert("Contact", sforceMapping);
        setExtIdField(oldExtIdField);
        configMap.put(AppConfig.PROP_ENTITY, "Task");
        runProcess(configMap, 1);
    }
    
    /**
     * Tests update operation with input coming from a CSV file. Relies on the id's in the CSV on being in the database
     */
    @Test
    public void testUpdateAccountCsv() throws Exception {
        Map<String, String> configMap = getUpdateTestConfig(false, null, 100);
        if (isSettingEnabled(configMap, AppConfig.PROP_BULK_API_ZIP_CONTENT)
                || isSettingEnabled(configMap, AppConfig.PROP_PROCESS_BULK_CACHE_DATA_FROM_DAO)
                || isSettingEnabled(configMap, AppConfig.PROP_BULK_API_SERIAL_MODE)
                || isSettingEnabled(configMap, AppConfig.PROP_NO_COMPRESSION)
                || isSettingEnabled(configMap, AppConfig.PROP_UPDATE_WITH_EXTERNALID)
                ) {
            return;
        }
        runProcess(configMap, 100);
    }
    
    @Test
    public void testUpdateAccountWithExternalIdCsv() throws Exception {
        Map<String, String> configMap = getUpdateTestConfig(false, null, 5);
        if (!isSettingEnabled(configMap, AppConfig.PROP_UPDATE_WITH_EXTERNALID)) {
            return;
        }
        runProcess(configMap, 5);
    }
    
    /**
     * Upsert the records from CSV file
     */
    @Test
    public void testUpsertAccountCsv() throws Exception {
        Map<String, String> configMap = getUpdateTestConfig(true, DEFAULT_ACCOUNT_EXT_ID_FIELD, 50);
        if (isSettingEnabled(configMap, AppConfig.PROP_BULK_API_ZIP_CONTENT)
                || isSettingEnabled(configMap, AppConfig.PROP_UPDATE_WITH_EXTERNALID)
                || isSettingEnabled(configMap, AppConfig.PROP_PROCESS_BULK_CACHE_DATA_FROM_DAO)
                || isSettingEnabled(configMap, AppConfig.PROP_BULK_API_SERIAL_MODE)
                || isSettingEnabled(configMap, AppConfig.PROP_NO_COMPRESSION)
                ) {
            return;
        }
        // manually inserts 50 accounts, then upserts 100 accounts (50 inserts and 50 updates)
        runUpsertProcess(configMap, 50, 50);
    }

    /**
     * Verify that when the constants are placed into the .sdl mapping file,
     * they are treated correctly. It tests that constants mapped on 1 field and
     * a constant mapped on 2 fields both get inserted correctly. This is more
     * of a basic test on the functionality and not an examination of corner
     * cases.
     *
     * @expectedResults Assert that the custom field values come back correctly
     *                  when queried.
     * @throws Exception
     */
    @Test
    public void testConstantMappingInCsv() throws Exception {
        Map<String, String> configMap = getTestConfig(OperationInfo.insert, false);
        if (isSettingEnabled(configMap, AppConfig.PROP_BULK_API_ZIP_CONTENT)
                || isSettingEnabled(configMap, AppConfig.PROP_PROCESS_BULK_CACHE_DATA_FROM_DAO)
                || isSettingEnabled(configMap, AppConfig.PROP_BULK_API_SERIAL_MODE)
                || isSettingEnabled(configMap, AppConfig.PROP_NO_COMPRESSION)
                ) {
            return;
        }
        // The use case is as follows:
        // This company in this scenario only does business in the state of CA, therefore billing and shipping
        // addresses are hard coded to that.
        // Also, all of its accounts are in the Aerospace Industry.

        final String stateValue = "California";
        final String industryValue = "Aerospace";

        // insert the values
        for (SObject acct : retrieveAccounts(runProcess(configMap, 2), "Industry", "BillingState", "ShippingState")) {

            assertEquals("Incorrect value for industry returned",
                    industryValue, acct.getField("Industry"));
            assertEquals("Incorrect value for billing state returned",
                    stateValue, acct.getField("BillingState"));
            assertEquals("Incorrect value for shipping state returned",
                    stateValue, acct.getField("ShippingState"));
        }
    }

    /**
     * Verify that the description field, which is of type 'LongTextArea', can be correctly placed as a constant.
     *
     * @expectedResults Assert that the custom field values come back correctly
     *                  when queried.
     *
     * @throws Exception
     */
    @Test
    public void testDescriptionAsConstantMappingInCsv() throws Exception {
        Map<String, String> configMap = getTestConfig(OperationInfo.insert, getTestDataDir()
                + "/constantMappingInCsv.csv", false);
        if (isSettingEnabled(configMap, AppConfig.PROP_BULK_API_ZIP_CONTENT)
                || isSettingEnabled(configMap, AppConfig.PROP_PROCESS_BULK_CACHE_DATA_FROM_DAO)
                || isSettingEnabled(configMap, AppConfig.PROP_BULK_API_SERIAL_MODE)
                || isSettingEnabled(configMap, AppConfig.PROP_NO_COMPRESSION)
                ) {
            return;
        }
        // The use case is as follows:
        // This company in this scenario only does business in the state of CA, therefore billing and shipping
        // addresses are hard coded to that.
        // Also, all of its descriptions are constant.
        final String stateValue = "California";
        final String descriptionValue = "Some Description";

        // insert the values

        Controller controller = runProcess(configMap, 2);
        for (SObject acct : retrieveAccounts(controller, "Description", "BillingState", "ShippingState")) {
            assertEquals("Incorrect value for billing state returned", stateValue, acct.getField("BillingState"));
            assertEquals("Incorrect value for shipping state returned", stateValue, acct.getField("ShippingState"));
            assertEquals("Incorrect value for description returned",
                    descriptionValue, acct.getField("Description"));
        }
    }

    /**
     * Verify that when a constant value is given in the CSV file for a given field, and that field
     * is also specified in the CSV, that the values from the CSV file take precedence.
     *
     * @expectedResults Assert that the values retrieved for that field match those in the CSV file
     */
    @Test
    public void testFieldAndConstantFieldClash()  throws Exception {
        Map<String, String> configMap = getTestConfig(OperationInfo.insert,
                getTestDataDir() + "/constantMappingInCsvClashing.csv", false);
        if (isSettingEnabled(configMap, AppConfig.PROP_BULK_API_ZIP_CONTENT)
                || isSettingEnabled(configMap, AppConfig.PROP_PROCESS_BULK_CACHE_DATA_FROM_DAO)
                || isSettingEnabled(configMap, AppConfig.PROP_BULK_API_SERIAL_MODE)
                || isSettingEnabled(configMap, AppConfig.PROP_NO_COMPRESSION)
                ) {
            return;
        }
        // The use case is as follows:
        // This company in this scenario only does business in the state of CA, therefore billing and shipping
        // addresses are hard coded to that.
        // **In this case, not all accounts are in the Aerospace industry.

        final String stateValue = "California";
        final String industryValue = "Aerospace";

        // insert the values
        for (SObject acct : retrieveAccounts(runProcess(configMap, 2), "Industry", "BillingState", "ShippingState")) {

            assertEquals("Incorrect value for industry returned",
                    industryValue, acct.getField("Industry"));
            assertEquals("Incorrect value for billing state returned",
                    stateValue, acct.getField("BillingState"));
            assertEquals("Incorrect value for shipping state returned",
                    stateValue, acct.getField("ShippingState"));
        }
    }

    /**
     * Verify that when the left side of a mapping is empty, "", or " ", the field returned is null
     *
     * @expectedResults Assert that the values retrieved for that field match those in the CSV file
     */
    @Test
    public void testNullConstantAssignment()  throws Exception {

        /* Field assignments in .sdl are as follows:
            ""=Industry
            " " = Description
            =AnnualRevenue
         */
        final String stateValue = "California";

        // insert the values
        Map<String, String> argumentMap = getTestConfig(OperationInfo.insert,
                getTestDataDir() + "/constantMappingInCsv.csv", false);

        for (SObject acct : retrieveAccounts(runProcess(argumentMap, 2), "Industry", "Description", "AnnualRevenue",
                "ShippingState")) {

            assertNull("Non-null value for industry returned",
                    acct.getField("Industry"));
            assertNull("Non-null value for billing state returned",
                    acct.getField("Description"));
            assertNull("Non-null value for shipping state returned",
                    acct.getField("AnnualRevenue"));

            //to verify a non-null placement as well
            assertEquals("Incorrect value for shipping state returned",
                    stateValue, acct.getField("ShippingState"));
        }
    }

    //Factor out the verification query
    private SObject[] retrieveAccounts(Controller resultController, String... accountFieldsToReturn) throws Exception {

        List<String> ids = new ArrayList<String>();
        String fileName = resultController.getAppConfig().getString(AppConfig.PROP_OUTPUT_SUCCESS);
        final CSVFileReader successRdr = new CSVFileReader(new File(fileName), getController().getAppConfig(), true, false);
        try {
            // TODO: revise the use of Integer.MAX_VALUE
            for (TableRow row : successRdr.readTableRowList(Integer.MAX_VALUE)) {
                final String rowId = (String) row.get("ID");
                if (rowId != null) {
                    ids.add(rowId);
                }
            }
        } finally {
            successRdr.close();
        }


        // query them and verify that they have the values
        StringBuilder fields = new StringBuilder("id");
        for(String field : accountFieldsToReturn) {
            fields.append(AppUtil.COMMA).append(field);
        }

        SObject[] sobjects = getBinding().retrieve(fields.toString(), "Account", ids.toArray(new String[ids.size()]));
        assertEquals("Wrong number of accounts created", ids.size(), sobjects.length);
        return sobjects;
    }

    /**
     * Tests Upsert on non-polymorphic foreign key (Relationship lookup) for the records 
     * using idlookup field of the parent object
     */
    @Test
    public void testUpsertFkAccountOldFormatCsv() throws Exception {
        Map<String, String> configMap = getTestConfig(OperationInfo.upsert, false);
        if (isSettingEnabled(configMap, AppConfig.PROP_UPDATE_WITH_EXTERNALID)) {
            return;
        }
        // manually inserts 100 accounts, then upserts specifying account parent for 50 accounts
        runUpsertProcess(getUpdateTestConfig(true, DEFAULT_ACCOUNT_EXT_ID_FIELD, 100), 0, 50);
    }
    
    @Test
    public void testUpsertFkAccountNewFormatCsv() throws Exception {
        Map<String, String> configMap = getTestConfig(OperationInfo.upsert, false);
        if (isSettingEnabled(configMap, AppConfig.PROP_UPDATE_WITH_EXTERNALID)) {
            return;
        }
        // manually inserts 100 accounts, then upserts specifying account parent for 5 accounts
        runUpsertProcess(getUpdateTestConfig(true, DEFAULT_ACCOUNT_EXT_ID_FIELD, 10), 0, 5);
    }

    /**
     * Tests that Deleting the records based on a CSV file works
     */
    @Test
    public void testDeleteAccountCsv() throws Exception {
        Map<String, String> configMap = getTestConfig(OperationInfo.delete, false);
        if (isSettingEnabled(configMap, AppConfig.PROP_UPDATE_WITH_EXTERNALID)) {
            return;
        }
        AccountIdTemplateListener listener = new AccountIdTemplateListener(100);
        String deleteFileName = convertTemplateToInput(baseName + "Template.csv", baseName + ".csv", listener);
        Map<String, String> argMap = getTestConfig(OperationInfo.delete, deleteFileName, false);
        Controller theController = runProcess(argMap, 100);
        String[] accountIds = listener.getAccountIds();
        verifySuccessIds(theController, accountIds);
        if (argMap.containsKey(AppConfig.PROP_BULK_API_ENABLED) && argMap.get(AppConfig.PROP_BULK_API_ENABLED).equalsIgnoreCase("true")) {
            return;
        }
        // partner API - do an undelete operation
        argMap.put(AppConfig.PROP_OPERATION, OperationInfo.undelete.name());
        theController = runProcess(argMap, 100);
        verifySuccessIds(theController, accountIds);
        argMap.put(AppConfig.PROP_OPERATION, OperationInfo.delete.name());
        theController = runProcess(argMap, 100);
        verifySuccessIds(theController, accountIds);
    }

    private class AttachmentTemplateListener extends AccountIdTemplateListener {
        public AttachmentTemplateListener() {
            super(1);
        }

        @Override
        public void updateRow(int idx, TableRow row) {
            // set parent account id
            row.put("ParentId", getAccountIds()[0]);
            // make body pathname absolute
            String filePath = (String)row.get("Body");
            row.put("Body", getTestDataDir() + File.separator + filePath);
        }
    }

    @Test
    public void testCreateAttachment() throws Exception {
        // convert the template using the parent account id
        final String fileName = convertTemplateToInput(this.baseName + "Template.csv", this.baseName + ".csv",
                new AttachmentTemplateListener());

        final Map<String, String> argMap = getTestConfig(OperationInfo.insert, fileName, false);
        argMap.put(AppConfig.PROP_ENTITY, "Attachment");
        if (isSettingEnabled(argMap, AppConfig.PROP_UPDATE_WITH_EXTERNALID)) {
            return;
        }
        if (isSettingEnabled(argMap, AppConfig.PROP_PROCESS_BULK_CACHE_DATA_FROM_DAO)) {
            return;
        }
        
        // this feature does not work when bulk api is enabled but the zip content type is not
        final boolean bulkApi = isBulkAPIEnabled(argMap);
        final boolean bulkV2Api = isBulkV2APIEnabled(argMap);
        final boolean zipContent = isSettingEnabled(argMap, AppConfig.PROP_BULK_API_ZIP_CONTENT);
        if ((bulkApi || bulkV2Api) && !zipContent) {
            final String failureMessage = "Data Loader cannot map \"Body\" field using Bulk API and CSV content type.  Please enable the ZIP_CSV content type for Bulk API.";
            runProcessNegative(argMap, failureMessage);
        } else if (bulkV2Api && zipContent) {
            final String failureMessage = "Exit UNSUPPORTEDCONTENTTYPE : UnsupportedContentType : ZIP_CSV is not a valid Content-Type";
            runProcessNegative(argMap, failureMessage);
        } else {
            runProcess(argMap, 1);
        }
    }

    /**
     * Verify that if not all columns are matched, that the DL operation cannot go forward.
     *
     * @expectedResults Assert that all the records were inserted and that the constant value was mapped as well.
     *
     */
    @Test
    public void testNonMappedFieldsPermittedInDLTransaction() throws Exception {

        final int numberOfRows = 4;
        final String hardCodedShippingState = "California";

        // insert the values
        Map<String, String> argumentMap = getTestConfig(OperationInfo.insert,
                getTestDataDir() + "/accountsForInsert.csv", false);
        if (isSettingEnabled(argumentMap, AppConfig.PROP_UPDATE_WITH_EXTERNALID)) {
            return;
        }
        SObject[] returnedAccounts = retrieveAccounts(runProcess(argumentMap, numberOfRows), "ShippingState",
                "Industry");

        //quick sanity check on the inserted record.
        for (SObject acct : returnedAccounts) {

            assertEquals("Incorrect value for Shipping state returned",
                    hardCodedShippingState, acct.getField("ShippingState"));

            assertNull("Industry field was populated though it was not mapped", acct.getField("Industry"));
        }
    }

    /**
     * Verify that if not all columns are matched, that the DL operation cannot go forward.
     *
     * @expectedResults Assert that all the records were inserted and that the constant value was mapped as well.
     *
     */
    @Test
    public void testHtmlFormattingInInsert() throws Exception {
        _doTestHtmlFormattingInInsert(true);
        _doTestHtmlFormattingInInsert(false);
    }
    
    private void _doTestHtmlFormattingInInsert(boolean preserveWhitespaceInRichText) throws Exception {
        final int NONBREAKING_SPACE_ASCII_VAL = 0xA0;
        final int numberOfRows = 4;

        // insert the values
        Map<String, String> argumentMap = getTestConfig(OperationInfo.insert,
                getTestDataDir() + "/accountsForInsert.csv", 
                getTestDataDir() + "/nonMappedFieldsPermittedInDLTransactionMap.sdl",
                false);
        if (isSettingEnabled(argumentMap, AppConfig.PROP_UPDATE_WITH_EXTERNALID)) {
            return;
        }
        if (isSettingEnabled(argumentMap, AppConfig.PROP_BULK_API_ZIP_CONTENT)
                || isSettingEnabled(argumentMap, AppConfig.PROP_PROCESS_BULK_CACHE_DATA_FROM_DAO)
                || isSettingEnabled(argumentMap, AppConfig.PROP_BULK_API_SERIAL_MODE)
                || isSettingEnabled(argumentMap, AppConfig.PROP_NO_COMPRESSION)
                ) {
            return;
        }
        argumentMap.put(AppConfig.PROP_LOAD_PRESERVE_WHITESPACE_IN_RICH_TEXT, 
                        Boolean.toString(preserveWhitespaceInRichText));


        SObject[] returnedAccounts = retrieveAccounts(runProcess(argumentMap, 
                                        numberOfRows), "RichText__c", "Name");

        for (SObject acct : returnedAccounts) {
            String companyName = (String)acct.getField("Name");
            String textWithSpaceChars = (String)acct.getField("RichText__c");
            textWithSpaceChars = textWithSpaceChars.replace((char)NONBREAKING_SPACE_ASCII_VAL, ' ');
            if (companyName.equalsIgnoreCase("Company A")) {
                boolean isHTMLFormattingPreserved = textWithSpaceChars.contains("<h1>");
                assertEquals("HTML formatting not preserved for company " + companyName,
                                true, isHTMLFormattingPreserved);
                isHTMLFormattingPreserved = textWithSpaceChars.contains("<span style=\"font-size: 172px;\"");
                assertEquals("HTML formatting not preserved for company " + companyName,
                        true, isHTMLFormattingPreserved);
            } else if (companyName.equalsIgnoreCase("Company B")) {
                boolean isHTMLFormattingPreserved = textWithSpaceChars.contains("<p>");
                assertEquals("HTML formatting not preserved for company " + companyName,
                        true, isHTMLFormattingPreserved);
                String spaces = textWithSpaceChars.substring(3,7);
                for (int i = 0; i < spaces.length(); i++) {
                    char c = spaces.charAt(i);
                    int cval = c;
                    boolean isSpaceChar = false;
                    if (cval == NONBREAKING_SPACE_ASCII_VAL || cval == ' ') {
                        isSpaceChar = true;
                    }
                    assertEquals("spaces not preserved for company " + companyName, true, isSpaceChar);
                }
                continue;
            } else if (companyName.equalsIgnoreCase("Company C")) {
                int idx = textWithSpaceChars.indexOf('<');
                if (idx == -1) {
                    idx = textWithSpaceChars.indexOf("&lt;");
                }
                if (idx != -1) {
                    idx += 4;
                    if (textWithSpaceChars.charAt(idx+1) != ' '
                        || textWithSpaceChars.charAt(idx+2) != ' '
                        || textWithSpaceChars.charAt(idx+1) != ' ') {
                        assertEquals("spaces after < character not preserved for company " + companyName, true, false);
                    }
                }
            }
            String textWithoutLeadingSpaceChars = textWithSpaceChars.stripLeading();
            String textWithoutTrailingSpaceChars = textWithSpaceChars.stripTrailing();
            int numLeadingChars = textWithSpaceChars.length() - textWithoutLeadingSpaceChars.length();
            int numTrailingChars = textWithSpaceChars.length() - textWithoutTrailingSpaceChars.length();
            if (preserveWhitespaceInRichText) {
                assertEquals("Incorrect value for RichText returned for " + companyName,
                        4, numLeadingChars);
                assertEquals("Incorrect value for RichText returned for " + companyName,
                        2, numTrailingChars);
            } else {
                assertEquals("Incorrect value for RichText returned for " + companyName,
                        0, numLeadingChars);
                assertEquals("Incorrect value for RichText returned for " + companyName,
                        0, numTrailingChars);
               
            }
        }
    }

    
    /**
     *
     * Verify that Date/Time with time zone, when truncated to just date, gets transferred and interpreted correctly.
     *
     * @expectedResults Assert that the dates in Salesforce match up.
     *
     */
    @Test
    public void testTimezoneNotTruncated() throws Exception {

        final int numberOfRows = 12;
        final int targetDate = 14;
        final String dateField = "CustomDateTime__c";

        TimeZone TZ = TimeZone.getTimeZone("GMT");

        DateTimeConverter converter = new DateTimeConverter(TZ, false);
        //find the csv file
        Map<String, String> argumentMap = getTestConfig(OperationInfo.insert,
                getTestDataDir() + "/timeZoneFormatTesting.csv", false);
        if (isSettingEnabled(argumentMap, AppConfig.PROP_BULK_API_ZIP_CONTENT)
                || isSettingEnabled(argumentMap, AppConfig.PROP_UPDATE_WITH_EXTERNALID)
                || isSettingEnabled(argumentMap, AppConfig.PROP_PROCESS_BULK_CACHE_DATA_FROM_DAO)
                || isSettingEnabled(argumentMap, AppConfig.PROP_BULK_API_SERIAL_MODE)
                || isSettingEnabled(argumentMap, AppConfig.PROP_NO_COMPRESSION)
                ) {
            return;
        }
        //insert into the account on the custom fields specified
        SObject[] returnedAccounts = retrieveAccounts(runProcess(argumentMap, numberOfRows), dateField);


        for (SObject acct : returnedAccounts) {

            String dateString = (String)acct.getField(dateField);
            Calendar calFromString = (Calendar) converter.convert(null, dateString);

            assertEquals("Day field does not match", targetDate, calFromString.get(Calendar.DAY_OF_MONTH));
        }
    }

    /**
     * Verify that the controller reports that errors occurred on invalid dates.
     *
     * @expectedResults Assert that the correct number of errors and successes are returned.
     *
     * @throws Exception
     */
    @Test
    public void testErrorsGeneratedOnInvalidDateMatching() throws Exception {

    	runTestErrorsGeneratedOnInvalidDateMatchWithOffset(0, 4, 2);
    }

    /**
     * Verify that the controller reports that errors occurred on invalid dates and works with row offsets.
     *
     * @expectedResults Assert that the correct number of errors and successes are returned.
     *
     * @throws Exception
     */
    @Test
    public void testErrorsGeneratedOnInvalidDateMatchingWithOffset() throws Exception {
    	runTestErrorsGeneratedOnInvalidDateMatchWithOffset(2, 3, 1);
    }
    
    @Test
    public void testOneToManySforceFieldsMappingInCsv() throws Exception {
        // The use case is as follows:
        // This company in this scenario only does business in the state of CA, therefore billing and shipping
        // addresses are hard coded to that.
        // Also, all of its descriptions are constant.

        // insert the values
        Map<String, String> argumentMap = getTestConfig(OperationInfo.insert, getTestDataDir()
                + "/oneToManySforceFieldsMappingInCsv.csv", false);
        if (isSettingEnabled(argumentMap, AppConfig.PROP_BULK_API_ZIP_CONTENT)
                || isSettingEnabled(argumentMap, AppConfig.PROP_UPDATE_WITH_EXTERNALID)
                || isSettingEnabled(argumentMap, AppConfig.PROP_PROCESS_BULK_CACHE_DATA_FROM_DAO)
                || isSettingEnabled(argumentMap, AppConfig.PROP_BULK_API_SERIAL_MODE)
                || isSettingEnabled(argumentMap, AppConfig.PROP_NO_COMPRESSION)
                ) {
            return;
        }
        Controller controller = runProcess(argumentMap, 2);
        for (SObject acct : retrieveAccounts(controller, "Name", "Description", "BillingState", "ShippingState")) {
            if ("ABC Corp".equals(acct.getField("Name"))) {
                final String stateValue = "California";
                assertEquals("Incorrect value for billing state returned", stateValue, acct.getField("BillingState"));
                assertEquals("Incorrect value for shipping state returned", stateValue, acct.getField("ShippingState"));
                assertEquals("Incorrect value for description returned", stateValue, acct.getField("Description"));
            } else if ("XYZ Corp".equals(acct.getField("Name"))) {
                final String stateValue = "New York";
                assertEquals("Incorrect value for billing state returned", stateValue, acct.getField("BillingState"));
                assertEquals("Incorrect value for shipping state returned", stateValue, acct.getField("ShippingState"));
                assertEquals("Incorrect value for description returned", stateValue, acct.getField("Description"));
            }
        }
        
        // test with insert nulls set to true.
        argumentMap.put(AppConfig.PROP_INSERT_NULLS, "true");
        controller = runProcess(argumentMap, 2);
        for (SObject acct : retrieveAccounts(controller, "Name", "Description", "BillingState", "ShippingState")) {
            if ("ABC Corp".equals(acct.getField("Name"))) {
                final String stateValue = "California";
                assertEquals("Incorrect value for billing state returned", stateValue, acct.getField("BillingState"));
                assertEquals("Incorrect value for shipping state returned", stateValue, acct.getField("ShippingState"));
                assertEquals("Incorrect value for description returned", stateValue, acct.getField("Description"));
            } else if ("XYZ Corp".equals(acct.getField("Name"))) {
                final String stateValue = "New York";
                assertEquals("Incorrect value for billing state returned", stateValue, acct.getField("BillingState"));
                assertEquals("Incorrect value for shipping state returned", stateValue, acct.getField("ShippingState"));
                assertEquals("Incorrect value for description returned", stateValue, acct.getField("Description"));
            }
        }
    }
    
    @Test
    public void testEmptyFirstRowFieldValueInCsv() throws Exception {
        Map<String, String> argumentMap = getUpdateTestConfig(false, null, 2);
        if (isSettingEnabled(argumentMap, AppConfig.PROP_BULK_API_ZIP_CONTENT)
                || isSettingEnabled(argumentMap, AppConfig.PROP_PROCESS_BULK_CACHE_DATA_FROM_DAO)
                || isSettingEnabled(argumentMap, AppConfig.PROP_BULK_API_SERIAL_MODE)
                || isSettingEnabled(argumentMap, AppConfig.PROP_NO_COMPRESSION)
                || isSettingEnabled(argumentMap, AppConfig.PROP_UPDATE_WITH_EXTERNALID)
                ) {
            return;
        }
        // update 2 records
        Controller controller = runProcess(argumentMap, 2);

        for (SObject acct : retrieveAccounts(controller, "Name", "Website")) {
            String websiteVal = (String)acct.getField("Website");
            String acctName = (String)acct.getField("Name");
            if ("account Update #1".equals(acctName)) {
                assertEquals("Incorrect value for field Website returned for the account " + acctName, "updated", websiteVal);
            }
        }
    }

    private void runTestErrorsGeneratedOnInvalidDateMatchWithOffset(Integer rowOffset, final int numSuccesses, final int numFailures) throws Exception {

    	//examine the error file and verify that the row in question failed
    	final int numberOfRows = 6;
        final int targetDate = 14;
        final String dateField = "CustomDateTime__c";

        assertEquals("Invalid testing configuration", numberOfRows, rowOffset + numFailures + numSuccesses);

        TimeZone TZ = TimeZone.getTimeZone("GMT");

        DateTimeConverter converter = new DateTimeConverter(TZ, false);
        //find the csv file
        Map<String, String> argumentMap = getTestConfig(OperationInfo.insert, getTestDataDir()
                + "/timeZoneFormatTestingWithErrors.csv", false);
        argumentMap.put(AppConfig.PROP_LOAD_ROW_TO_START_AT, rowOffset.toString());
        if (isSettingEnabled(argumentMap, AppConfig.PROP_UPDATE_WITH_EXTERNALID)) {
            return;
        }

        // insert into the account on the custom fields specified
        Controller controller = runProcessWithErrors(argumentMap, numSuccesses, numFailures);

        verifyErrors(controller, "Error converting value to correct data type: Failed to parse date: ");

        SObject[] returnedAccounts = retrieveAccounts(controller, dateField);

        // TODO this verification shouldn't be here necessarily. move it to DateProcessTest
        for (SObject acct : returnedAccounts) {

            String dateString = (String)acct.getField(dateField);

            Calendar.getInstance(TZ);
            Calendar calFromString = (Calendar)converter.convert(null, dateString);

            assertEquals("Day field does not match", targetDate, calFromString.get(Calendar.DAY_OF_MONTH));
        }
    }
}

