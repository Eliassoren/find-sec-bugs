package com.h3xstream.findsecbugs.oauth2;

import com.h3xstream.findbugs.test.BaseDetectorTest;
import com.h3xstream.findbugs.test.EasyBugReporter;
import org.testng.annotations.Test;

import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

public class OidcPasswordGrantTest extends BaseDetectorTest{
    @Test
    public void usingUnsafePasswordGrantTest() throws Exception {
        //Locate test code
        String[] files = {
                getClassFilePath("testcode/oidc/nimbus/OidcPasswordGrant")
        };

        //Run the analysis
        EasyBugReporter reporter = spy(new BaseDetectorTest.SecurityReporter());
        analyze(files, reporter);


        //Assertions
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("USING_PASSWORD_GRANT_OAUTH")
                        .inClass("OidcPasswordGrant")
                        .inMethod("authenticate")
                        .build()
        );
    }
}
