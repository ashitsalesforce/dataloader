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
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;

import com.salesforce.dataloader.action.OperationInfo;
import com.salesforce.dataloader.config.AppConfig;
import com.salesforce.dataloader.dao.csv.CSVFileReader;
import com.salesforce.dataloader.exception.DataAccessObjectException;
import com.salesforce.dataloader.exception.DataAccessObjectInitializationException;
import com.salesforce.dataloader.exception.ProcessInitializationException;
import com.salesforce.dataloader.model.TableRow;
import com.sforce.async.CSVReader;
import com.sforce.soap.partner.sobject.SObject;
import com.sforce.ws.ConnectionException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Set of tests to verify that aggregate queries can be used to extract data
 * and that results are mapped correctly in the output file.
 *
 * @author Federico Recio
 */
public class CsvExtractAggregateQueryProcessTest extends ProcessTestBase {

    private Map<String,String> testConfig;

    @Before
    public void setUpTestConfig() {
        testConfig = getTestConfig(OperationInfo.extract, true);
        testConfig.put(AppConfig.PROP_ENTITY, "Contact");
        testConfig.put(AppConfig.PROP_ENABLE_EXTRACT_STATUS_OUTPUT, AppConfig.TRUE);
        testConfig.remove(AppConfig.PROP_MAPPING_FILE);
    }

    @Test
    public void testAggregateQuery() throws Exception {
        String accountId = insertAccount("acctNameXyz");
        String contactId = insertContact(accountId);
        runExtraction("select Count(Id), Account.Name from Contact where Id='" + contactId + "' GROUP BY Account.Name");
        validateAccountNameInOutputFile("acctNameXyz", true);
        runExtractionDoNotLimitOutputToQueryFields("select Count(Id), Account.Name from Contact where Id='" + contactId + "' GROUP BY Account.Name");
        validateAccountNameInOutputFile("acctNameXyz", false);
    }

    private void runExtraction(String extractionQuery) throws ProcessInitializationException, DataAccessObjectException {
        testConfig.put(AppConfig.PROP_EXTRACT_SOQL, extractionQuery);
        testConfig.put(AppConfig.PROP_LIMIT_OUTPUT_TO_QUERY_FIELDS, AppConfig.TRUE);
        runProcess(testConfig, 1, true);
    }

    private void runExtractionDoNotLimitOutputToQueryFields(String extractionQuery) throws ProcessInitializationException, DataAccessObjectException {
        testConfig.put(AppConfig.PROP_EXTRACT_SOQL, extractionQuery);
        testConfig.put(AppConfig.PROP_LIMIT_OUTPUT_TO_QUERY_FIELDS, AppConfig.FALSE);
        runProcess(testConfig, 1, true);
    }

    private void validateAccountNameInOutputFile(final String accountName, boolean isLimitOutputToQueryFields) throws IOException {
        FileInputStream fis = new FileInputStream(new File(testConfig.get(AppConfig.PROP_DAO_NAME)));
        try {
            CSVFileReader rdr = new CSVFileReader(new File(testConfig.get(AppConfig.PROP_DAO_NAME)),
                    this.getController().getAppConfig(), false, true);
            rdr.open();
            TableRow row = rdr.readTableRow();
            String extractedNameVal = (String)row.get("Name");
            if (isLimitOutputToQueryFields) {
                extractedNameVal = (String)row.get("Account.Name");
            }
            assertEquals(accountName, extractedNameVal);
        } catch (DataAccessObjectInitializationException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (DataAccessObjectException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } finally {
            IOUtils.closeQuietly(fis);
        }
    }

    private String insertAccount(String name) throws ConnectionException {
        final SObject account = new SObject();
        account.setType("Account");
        account.setField("Name", name);
        String id = getBinding().create(new SObject[]{account})[0].getId();
        assertNotNull(id);
        return id;
    }

    private String insertContact(String accountId) throws ConnectionException {
        final SObject contact = new SObject();
        contact.setType("Contact");
        contact.setField("AccountId", accountId);
        contact.setField("LastName", "Abc");
        String id = getBinding().create(new SObject[]{contact})[0].getId();
        assertNotNull(id);
        return id;
    }
}
