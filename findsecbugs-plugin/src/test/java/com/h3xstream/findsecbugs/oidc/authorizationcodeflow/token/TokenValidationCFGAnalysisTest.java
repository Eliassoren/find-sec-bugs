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

