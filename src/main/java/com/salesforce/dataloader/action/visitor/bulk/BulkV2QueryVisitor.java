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

package com.salesforce.dataloader.action.visitor.bulk;

import java.io.IOException;
import java.io.InputStream;

import com.salesforce.dataloader.action.AbstractExtractAction;
import com.salesforce.dataloader.action.progress.ILoaderProgress;
import com.salesforce.dataloader.controller.Controller;
import com.salesforce.dataloader.dao.DataWriterInterface;
import com.salesforce.dataloader.exception.DataAccessObjectException;
import com.salesforce.dataloader.exception.ExtractException;
import com.salesforce.dataloader.exception.OperationException;
import com.sforce.async.AsyncApiException;


/**
 * Query visitor for bulk api extract operations.
 * 
 * @author Colin Jarvis
 * @since 21.0
 */
public class BulkV2QueryVisitor extends AbstractBulkQueryVisitor {

    private String jobId;

    public BulkV2QueryVisitor(AbstractExtractAction action, Controller controller, ILoaderProgress monitor, DataWriterInterface queryWriter,
            DataWriterInterface successWriter, DataWriterInterface errorWriter) {
        super(action, controller, monitor, queryWriter, successWriter, errorWriter);
    }

    @Override
    protected int executeQuery(String soql) throws AsyncApiException, OperationException {
        final BulkApiVisitorUtil jobUtil = new BulkApiVisitorUtil(getController(), getProgressMonitor(),
                getRateCalculator(), false);
        jobUtil.createJob(soql);
        this.jobId = jobUtil.getJobId();
        jobUtil.awaitCompletionAndCloseJob();
        return jobUtil.getRecordsProcessed();
    }

    @Override
    protected void writeExtraction() throws AsyncApiException, ExtractException, DataAccessObjectException {
        BulkV2Connection v2Conn = getController().getBulkV2Client().getConnection();
        try {
            InputStream serverResultStream = v2Conn.getQueryResultStream(this.jobId, "");
            writeExtractionForServerStream(serverResultStream);
            String locator = v2Conn.getQueryLocator();
            while (!"null".equalsIgnoreCase(locator)) {
                serverResultStream = v2Conn.getQueryResultStream(this.jobId, locator);
                writeExtractionForServerStream(serverResultStream);
                locator = v2Conn.getQueryLocator();
            }
        }   catch (final IOException e) {
            throw new ExtractException(e);
        }
    }
}
