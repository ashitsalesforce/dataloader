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

package com.salesforce.dataloader.dyna;

import java.text.*;
import java.util.*;

import com.salesforce.dataloader.model.NACalendarValue;
import com.salesforce.dataloader.model.NATextValue;
import org.apache.commons.beanutils.ConversionException;
import org.apache.commons.beanutils.Converter;
import org.apache.logging.log4j.Logger;
import com.salesforce.dataloader.util.DLLogManager;

public class DateTimeConverter implements Converter {

    static final TimeZone GMT_TZ = TimeZone.getTimeZone("GMT");
    static final List<String> supportedEuropeanPatterns = getSupportedPatterns(true);
    static final List<String> supportedRegularPatterns = getSupportedPatterns(false);

    static Logger logger = DLLogManager.getLogger(DateTimeConverter.class);
    /**
     * Should we return the default value on conversion errors?
     */
    final boolean useEuroDates;
    final TimeZone timeZone;

    public DateTimeConverter(TimeZone tz, boolean useEuroDateFormat) {
        this.timeZone = tz;
        this.useEuroDates = useEuroDateFormat;
    }

    private Calendar parseDate(String dateString, DateFormat fmt) {
        final ParsePosition pos = new ParsePosition(0);
        fmt.setLenient(false);
        final Date date = fmt.parse(dateString, pos);
        // we only want to use the date if parsing succeeded and used the entire string
        if (date != null && pos.getIndex() == dateString.length()) {
            Calendar cal = getCalendar(fmt.getTimeZone());
            cal.setTimeInMillis(date.getTime());
            return cal;
        }
        return null;
    }

    @Override
    @SuppressWarnings({ "rawtypes", "unchecked" })
    public Object convert(Class type, Object value) {
        if (value == null) {
            return null;
        }

        if(value instanceof NATextValue) {
            return getNAValueCalendar();
        }

        if (value instanceof Calendar) { return value; }
        
        Calendar cal = getCalendar(this.timeZone);
        if (value instanceof Date) {
            cal.setTimeInMillis(((Date)value).getTime());
            return cal;
        }

        String dateString = value.toString().trim();
        int len = dateString.length();

        if (len == 0) return null;

        TimeZone timeZoneForValue = this.timeZone;
        if ("z".equalsIgnoreCase(dateString.substring(len - 1))) {
            dateString = dateString.substring(0, len - 1);
            timeZoneForValue = GMT_TZ;
        }

        for (String pattern : useEuroDates ? supportedEuropeanPatterns : supportedRegularPatterns) {
            final DateFormat df = new SimpleDateFormat(pattern);
            df.setTimeZone(timeZoneForValue);
            cal = parseDate(dateString, df);
            if (cal != null) return cal;
        }

        DateFormat df = DateFormat.getDateTimeInstance(DateFormat.DEFAULT, DateFormat.DEFAULT);
        df.setTimeZone(this.timeZone);
        cal = parseDate(dateString, df);
        if (cal != null) return cal;

        df = DateFormat.getDateInstance(DateFormat.SHORT);
        df.setTimeZone(this.timeZone);
        cal = parseDate(dateString, df);
        if (cal != null) return cal;

        throw new ConversionException("Failed to parse date: " + value);
    }
    
    // NOTE: Always use this method to get Calendar instance
    protected Calendar getCalendar(TimeZone timezone) {
        return Calendar.getInstance(timezone);
    }
    
    protected Calendar getNAValueCalendar() {
        return NACalendarValue.getInstance();
    }

    /*
     * Helper function to produce all the patterns that DL supports.
     * These patterns are a subset of patterns supported by Java text.SimpleDateFormat
     * https://docs.oracle.com/javase/8/docs/api/java/text/SimpleDateFormat.html
     */
    private static List<String> getSupportedPatterns(boolean europeanDates) {

        List<String> basePatterns = new ArrayList<String>();

        // Extended patterns means using the - delimiter in the date

        List<String> extendedPatterns = new ArrayList<String>();
        extendedPatterns.add("yyyy-MM-dd'T'HH:mm:ss.SSS");
        extendedPatterns.add("yyyy-MM-dd'T'HH:mm:ss");
        extendedPatterns.add("yyyy-MM-dd'T'HH:mm");
        extendedPatterns.add("yyyy-MM-dd'T'HH");
        extendedPatterns.add("yyyy-MM-dd'T'"); //?
        extendedPatterns.add("yyyy-MM-dd");

        //As per ISO 8601 5.2.1.1, when only the days are omitted, a - is necessary between year and month
        List<String> extendedPatternsDateOnly = new ArrayList<String>();
        extendedPatternsDateOnly.add("yyyy-MM");
        extendedPatternsDateOnly.add("yyyyMMdd");
        extendedPatternsDateOnly.add("yyyy");

        // Using a space instead of 'T' to separate date and time
        List<String> extendedPatternsWithoutT = new ArrayList<String>();
        extendedPatternsWithoutT.add("yyyy-MM-dd HH:mm:ss.SSS");
        extendedPatternsWithoutT.add("yyyy-MM-dd HH:mm:ss");
        extendedPatternsWithoutT.add("yyyy-MM-dd HH:mm");
        extendedPatternsWithoutT.add("yyyy-MM-dd HH");

        // Not using anything to deliminate the date elements from each
        // other. Matched through known lengths of components.
        List<String> basicPatterns = new ArrayList<String>();
        basicPatterns.add("yyyyMMdd'T'HH:mm:ss.SSS");
        basicPatterns.add("yyyyMMdd'T'HH:mm:ss");
        basicPatterns.add("yyyyMMdd'T'HH:mm");
        basicPatterns.add("yyyyMMdd'T'HH");
        basicPatterns.add("yyyyMMdd'T'"); //?

        // Using a space instead of 'T' to separate date and time
        List<String> basicPatternsWithoutT = new ArrayList<String>();
        basicPatternsWithoutT.add("yyyyMMdd HH:mm:ss.SSS");
        basicPatternsWithoutT.add("yyyyMMdd HH:mm:ss");
        basicPatternsWithoutT.add("yyyyMMdd HH:mm");
        basicPatternsWithoutT.add("yyyyMMdd HH");

        //as per the iso 8601 spec
        List<String> fullBasicFormats = new ArrayList<String>();
        fullBasicFormats.add("yyyyMMdd'T'HHmmss");
        fullBasicFormats.add("yyyyMMdd'T'HHmm");
        fullBasicFormats.add("yyyyMMdd'T'HH");


        List<String> fullBasicFormatsWithoutT = new ArrayList<String>();
        fullBasicFormatsWithoutT.add("yyyyMMdd HHmmss");
        fullBasicFormatsWithoutT.add("yyyyMMdd HHmm");
        fullBasicFormatsWithoutT.add("yyyyMMdd HH");


        String baseDate = europeanDates ? "dd/MM/yyyy" : "MM/dd/yyyy";

        // Using a space instead of 'T' to separate date and time
        List<String> slashPatternsWithoutT = new ArrayList<String>();
        slashPatternsWithoutT.add(baseDate +" HH:mm:ss.SSS");
        slashPatternsWithoutT.add(baseDate +" HH:mm:ss");
        slashPatternsWithoutT.add(baseDate +" HH:mm");
        slashPatternsWithoutT.add(baseDate +" HH");
        slashPatternsWithoutT.add(baseDate +" HHZ");
        slashPatternsWithoutT.add(baseDate);

        List<String> slashPatternsWithT = new ArrayList<String>();
        slashPatternsWithT.add(baseDate +  "'T'HH:mm:ss.SSS");
        slashPatternsWithT.add(baseDate +  "'T'HH:mm:ss");
        slashPatternsWithT.add(baseDate +  "'T'HH:mm");
        slashPatternsWithT.add(baseDate +  "'T'HH");

        //order is important here because if it matches against the wrong format first, it will
        //misinterpret the time

        basePatterns.addAll(fullBasicFormatsWithoutT);
        basePatterns.addAll(fullBasicFormats);
        basePatterns.addAll(basicPatterns);
        basePatterns.addAll(basicPatternsWithoutT);
        basePatterns.addAll(extendedPatternsDateOnly);
        basePatterns.addAll(extendedPatterns);
        basePatterns.addAll(extendedPatternsWithoutT);
        basePatterns.addAll(slashPatternsWithoutT);
        basePatterns.addAll(slashPatternsWithT);
        
        List<String> timeZones = new ArrayList<>();
        // uppercase Z => RFC822 TimeZone
        basePatterns.forEach(p -> timeZones.add(p + "Z"));
        basePatterns.forEach(p -> timeZones.add(p + " Z"));

        // uppercase X => ISO8601 TimeZone
        basePatterns.forEach(p -> timeZones.add(p + "XXX"));
        basePatterns.forEach(p -> timeZones.add(p + " XXX"));

        basePatterns.forEach(p -> timeZones.add(p + "'Z'Z"));
        basePatterns.forEach(p -> timeZones.add(p + "'z'Z"));
        basePatterns.forEach(p -> timeZones.add(p + "z"));

        basePatterns.addAll(timeZones);

        return basePatterns;
    }
}