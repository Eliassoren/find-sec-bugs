/**
 * Find Security Bugs
 * Copyright (c) Philippe Arteau, All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 */
package com.h3xstream.findsecbugs.oidc.authorizationcodeflow.token;

import com.h3xstream.findbugs.test.BaseDetectorTest;
import com.h3xstream.findbugs.test.EasyBugReporter;
import org.testng.annotations.Test;
import static org.mockito.Mockito.*;

public class TokenValidationCFGAnalysisTest extends BaseDetectorTest {
    @Test
    public void improperReturnAfterAllFiveConditionalTest() throws Exception {
        //Locate test code
        String[] files = {
              getClassFilePath("testcode/oidc/googleapiclient/OidcValidateTokensGoogle"),
               // getClassFilePath("testcode/oidc/otherexamples/SimpleCFG")
        };

        //Run the analysis
        EasyBugReporter reporter = spy(new BaseDetectorTest.SecurityReporter());
        analyze(files, reporter);

        //Assertions
        verify(reporter, times(5)).doReportBug(
                bugDefinition()
                        .bugType("IMPROPER_TOKEN_VERIFY_CONTROL_FLOW")
                        .inClass("OidcValidateTokensGoogle")
                        .inMethod("validateTokensCompleteIncorrectReturn")
                        .build()
        );

        //Assertions
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("IMPROPER_TOKEN_VERIFY_CONTROL_FLOW")
                        .inClass("OidcValidateTokensGoogle")
                        .inMethod("validateTokensIncorrectReturn")
                        .build()
        );
    }

    @Test
    public void improperIfConditionalTest() throws Exception {
        //Locate test code
        String[] files = {
                getClassFilePath("testcode/oidc/googleapiclient/OidcValidateTokensGoogle"),
        };

        //Run the analysis
        EasyBugReporter reporter = spy(new BaseDetectorTest.SecurityReporter());
        analyze(files, reporter);

        //Assertions
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("REVERSED_IF_EQUALS_ID_TOKEN_VERIFY")
                        .inClass("OidcValidateTokensGoogle")
                        .inMethod("validateTokensReversedIfConditional")
                        .build()
        );
    }
}

