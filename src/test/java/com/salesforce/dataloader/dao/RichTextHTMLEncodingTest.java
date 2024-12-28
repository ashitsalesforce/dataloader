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
package com.salesforce.dataloader.dao;

import static org.junit.Assert.assertEquals;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.text.StringEscapeUtils;
import org.junit.Ignore;
import org.junit.Test;

import com.salesforce.dataloader.ConfigTestBase;
import com.salesforce.dataloader.action.visitor.DAOLoadVisitor;
import com.salesforce.dataloader.config.AppConfig;

public class RichTextHTMLEncodingTest extends ConfigTestBase {
    String regex = AppConfig.DEFAULT_RICHTEXT_REGEX;

    @Test
    public void testNoHTMLTags() throws Exception {
        String origText = "    a  ";
        String convertedText = DAOLoadVisitor.preserveWhitespaceInRichText(origText, regex);
        assertEquals("Incorrect encoding of whitespace characters in string" + origText,
                4, getSpaceChars(convertedText.substring(0, 24)));
        assertEquals("Incorrect encoding of whitespace characters in string" + origText,
                2, getSpaceChars(convertedText.substring(25)));

    }
    
    @Test
    public void testHTMLTagAttrsWithDoubleQuotes() throws Exception {    
        String tag = "<span style=\"font-size: 172px;\">";
        String origText = tag + "    a</span>  ";
        String convertedText = DAOLoadVisitor.preserveWhitespaceInRichText(origText, regex);
        assertEquals("Incorrect encoding of whitespace characters in string" + origText,
                4, getSpaceChars(convertedText.substring(
                        tag.length(), 
                        tag.length()+24)));
        assertEquals("Incorrect encoding of whitespace characters in string" + origText,
                2, getSpaceChars(convertedText.substring(tag.length()+30)));  
    }
    
    @Test
    public void testHTMLTagWithoutClosingQuote() throws Exception {    
        String tag = "<span style=\"font-size: 172px;>"; // skip closing doublequotes in style attribute
        String origText = tag + "    a  </p>";
        String convertedText = DAOLoadVisitor.preserveWhitespaceInRichText(origText, regex);
        assertEquals("Incorrect conversion of " + origText, "&lt;", convertedText.substring(0, 4));
    }
    
    @Test
    public void testHTMLTagAttrsWithSingleQuotes() throws Exception {    
        String tag = "<span style=\'font-size: 172px;\'>";
        String origText = tag + "    a</span    >  ";
        String convertedText = DAOLoadVisitor.preserveWhitespaceInRichText(origText, regex);
        assertEquals("Incorrect encoding of whitespace characters in string" + origText,
                4, getSpaceChars(convertedText.substring(
                        tag.length(), 
                        tag.length()+24)));
        assertEquals("Incorrect encoding of whitespace characters in string" + origText,
                2, getSpaceChars(convertedText.substring(tag.length()+34)));
    }
    
    @Test
    public void testLTAndGTCharsInString() throws Exception {    
        String origText = "    <0    or >1 ";
        String convertedText = DAOLoadVisitor.preserveWhitespaceInRichText(origText, regex);
        assertEquals("Incorrect encoding of whitespace characters in string" + origText,
                true, convertedText.contains("&lt;")); // text interpret as containing a HTML tag

        origText = "    <div ";
        convertedText = DAOLoadVisitor.preserveWhitespaceInRichText(origText, regex);
        assertEquals("Incorrect encoding of whitespace characters in string" + origText,
                true, convertedText.contains("&lt;")); // text interpret as containing a HTML tag

        origText = "    <div/> ";
        convertedText = DAOLoadVisitor.preserveWhitespaceInRichText(origText, regex);
        assertEquals("Incorrect encoding of whitespace characters in string" + origText,
                true, convertedText.contains("<")); // text interpret as containing a HTML tag
 
        origText = "    </div> ";
        convertedText = DAOLoadVisitor.preserveWhitespaceInRichText(origText, regex);
        assertEquals("Incorrect encoding of whitespace characters in string" + origText,
                true, convertedText.contains("<")); // text interpret as containing a HTML tag
        
        origText = "    < /div> ";
        convertedText = DAOLoadVisitor.preserveWhitespaceInRichText(origText, regex);
        assertEquals("Incorrect encoding of whitespace characters in string" + origText,
                true, convertedText.contains("&lt;")); // text interpret as containing a HTML tag

    }
    
    @Test
    public void testCascadingHTMLTags() throws Exception {    
        String tag = 
                  "<p>    "
                +   "<strong>leading</strong>"
                +   "     space "
                +   "<em>and</em>"
                +   " <u>ending</u>"
                +   " <strike>tab</strike>"
                + "</p>"
                + "<ol>"
                +   "<li><strike>line 1</strike>"
                +       "<ol>"
                +           "<li><strike>line 1a    </strike>    </li>"
                +           "<li><strike>line 1b<</strike>></li>"
                +       "</ol>"
                +   "</li>"
                +   "<li>"
                +       "<strike>line 2 </strike>"
                +   "</li>"
                + "</ol>\n"
                + "";
        String origText = tag + "    a  </p>";
        String convertedText = DAOLoadVisitor.preserveWhitespaceInRichText(origText, regex);
        assertEquals("Incorrect conversion of " + origText, "<", convertedText.substring(0, 1));
        String[] parts = convertedText.split("1a");
        assertEquals("Incorrect encoding of whitespace characters in string" + origText, 2, parts.length);
        assertEquals("Incorrect encoding of whitespace characters in string" + origText,
                4, getSpaceChars(parts[1].substring(0,25)));
        
        // verify that the first < char and the 2nd > char in the line "line 1b" are HTML encoded
        parts = convertedText.split("1b");
        assertEquals("Incorrect encoding of whitespace characters in string" + origText, 2, parts.length);
        assertEquals("Incorrect encoding of whitespace characters in string" + origText,
                "&lt;", parts[1].substring(0,4));
        
        parts = parts[1].split("</li>");
        parts = parts[0].split("</strike>");
        assertEquals("Incorrect encoding of whitespace characters in string" + origText,
                "&gt;", parts[1].substring(0,4));
    }
    
    @Test
    public void testSingleHTMLTagNoWhitespaceInText() throws Exception {    
        String origText = "<img   alt=\"dlscreenshot\"   src=\"https://ashit-dev-ed.file.force.com/sfc/servlet.shepherd/version/renditionDownload?rendition=ORIGINAL_Png&versionId=0684W00000eYv7k&operationContext=CHATTER&contentId=05T4W000020p7wj\"></img>";
        String convertedText = DAOLoadVisitor.preserveWhitespaceInRichText(origText, regex);
        assertEquals("Incorrect conversion of " + origText, origText.length(), convertedText.length());
    }
    
    @Test
    public void testMultipleHTMLTagNoWhitespaceInText() throws Exception {    
        String origText = "<br></br><br/><br>";
        String convertedText = DAOLoadVisitor.preserveWhitespaceInRichText(origText, regex);
        assertEquals("Incorrect conversion of " + origText, origText.length(), convertedText.length());
    }
    
    @Test
    public void testHTMLTagsAndLineBreaks() throws Exception {    
        String origText = "1\n2\r\n3\r<p>a</p><p>b</p><p>c</p>";
        String convertedText = DAOLoadVisitor.preserveWhitespaceInRichText(origText, regex);
        // preserveWhitespaceInRichText() should convert newline chars into a space char ' '
        assertEquals("Incorrect conversion of " + origText, origText.length(), convertedText.length()+1);
    }
    
    @Test
    public void testNoHTMLTagsAndLineBreaks() throws Exception {    
        String origText = "1\n2\r\n3\r";
        String convertedText = DAOLoadVisitor.preserveWhitespaceInRichText(origText, regex);
        // preserveWhitespaceInRichText() should convert newline chars into html tag "<br/>"
        assertEquals("Incorrect conversion of " + origText, origText.length(), convertedText.length()-11);
    }
    
    @Test
    public void testHTMLEncodedString() throws Exception {
        String origText = "  &amp; & < * $ ~ % &quot;6400L -37° &#127752; \n1  \r2  \r\n3";
        String convertedText = DAOLoadVisitor.preserveWhitespaceInRichText(origText, regex);
        int diff = convertedText.length() - origText.length();
        assertEquals("Incorrect conversion of " + origText, origText.length() + 45, convertedText.length());

        String unescapedOrigText = StringEscapeUtils.unescapeHtml4(origText);
        String unescapedConvertedText = StringEscapeUtils.unescapeHtml4(convertedText);
        diff = unescapedConvertedText.length() - unescapedOrigText.length();
        assertEquals("Incorrect conversion of " + origText,
                unescapedOrigText.length()+11,
                unescapedConvertedText.length());
    }


    private static final String HTML_WHITESPACE_ENCODING = "&nbsp;";
    private static final Pattern HTML_WHITESPACE_PATTERN = Pattern.compile(HTML_WHITESPACE_ENCODING);

    private int getSpaceChars(String text) {
        Matcher matcher = HTML_WHITESPACE_PATTERN.matcher(text);
        int count = 0;
        while (matcher.find()) {
            count++;
        }
        return count;
    }
}
