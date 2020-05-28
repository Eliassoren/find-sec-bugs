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
package com.h3xstream.findsecbugs.oidc.authorizationcodeflow.callback;

import com.h3xstream.findbugs.test.BaseDetectorTest;
import com.h3xstream.findbugs.test.EasyBugReporter;
import org.testng.annotations.Test;

import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

public class MissingCheckStateOidcDetectorTest extends BaseDetectorTest {

    @Test
    public void forgotToCheckStateTestNimbusSDK() throws Exception {
        //Locate test code
        String[] files = {
                getClassFilePath("testcode/oidc/nimbus/OidcCallbackVerifyStateNimbus")
        };

        //Run the analysis
        EasyBugReporter reporter = spy(new BaseDetectorTest.SecurityReporter());
        analyze(files, reporter);


        //Assertions
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("MISSING_VERIFY_OIDC_STATE")
                        .inClass("OidcCallbackVerifyStateNimbus")
                        .inMethod("callBackMissingCheckState")
                        .build()
        );
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("MISSING_VERIFY_OIDC_STATE")
                        .inClass("OidcCallbackVerifyStateNimbus")
                        .inMethod("callBackMissingCheckStatePassedParam")
                        .build()
        );
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("MISSING_VERIFY_OIDC_STATE")
                        .inClass("OidcCallbackVerifyStateNimbus")
                        .inMethod("stateMatcherHandleNoMatch")
                        .build()
        );
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("EXTERNAL_CALL_POSSIBLY_MISSING_VERIFY_OIDC_STATE")
                        .inClass("OidcCallbackVerifyStateNimbus")
                        .inMethod("callBackMissingCheckStatePassedParamForeign")
                        .build()
        );



    }

    @Test
    public void forgotToCheckStateTestGoogleSDK() throws Exception {
        //Locate test code
        String[] files = {
                getClassFilePath("testcode/oidc/googleapiclient/OidcCallbackVerifyStateGoogle")
        };

        //Run the analysis
        EasyBugReporter reporter = spy(new BaseDetectorTest.SecurityReporter());
        analyze(files, reporter);

        //Assertions
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("MISSING_VERIFY_OIDC_STATE")
                        .inClass("OidcCallbackVerifyStateGoogle")
                        .inMethod("callbackMissingCheckState")
                        .build()
        );
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("MISSING_VERIFY_OIDC_STATE")
                        .inClass("OidcCallbackVerifyStateGoogle")
                        .inMethod("callbackMissingCheckStatePassedToOther")
                        .build()
        );
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("MISSING_VERIFY_OIDC_STATE")
                        .inClass("OidcCallbackVerifyStateGoogle")
                        .inMethod("passStateNoCheck")
                        .build()
        );
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("EXTERNAL_CALL_POSSIBLY_MISSING_VERIFY_OIDC_STATE")
                        .inClass("OidcCallbackVerifyStateGoogle")
                        .inMethod("callbackMissingCheckStatePassedForeign")
                        .build()
        );
    }
}
