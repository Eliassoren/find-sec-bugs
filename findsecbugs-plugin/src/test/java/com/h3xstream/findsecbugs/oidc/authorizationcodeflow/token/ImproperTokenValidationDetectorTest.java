package com.h3xstream.findsecbugs.oidc.authorizationcodeflow.token;

import com.h3xstream.findbugs.test.BaseDetectorTest;
import com.h3xstream.findbugs.test.EasyBugReporter;
import org.testng.annotations.Test;

import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

public class ImproperTokenValidationDetectorTest extends BaseDetectorTest {

    @Test
    public void forgotToCheckTokenTestGoogleApiClient() throws Exception {
        //Locate test code
        String[] files = {
                getClassFilePath("testcode/oidc/googleapiclient/OidcValidateTokensGoogle")
        };

        //Run the analysis
        EasyBugReporter reporter = spy(new BaseDetectorTest.SecurityReporter());
        analyze(files, reporter);


        //Assertions
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("MISSING_VERIFY_ID_TOKEN")
                        .inClass("OidcValidateTokensGoogle")
                        .inMethod("tokenRequestNoValidation")
                        .build()
        );




    }
}
