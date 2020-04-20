package com.h3xstream.findsecbugs.oauth2;

import com.h3xstream.findbugs.test.BaseDetectorTest;
import com.h3xstream.findbugs.test.EasyBugReporter;
import org.testng.annotations.Test;

import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

public class ImproperStateUsageOidcTest extends BaseDetectorTest{
    @Test
    public void forgotToCheckStateTest() throws Exception {
        //Locate test code
        String[] files = {
                getClassFilePath("testcode/oidc/nimbus/OidcAuthenticationRequestStateUsage")
        };

        //Run the analysis
        EasyBugReporter reporter = spy(new BaseDetectorTest.SecurityReporter());
        analyze(files, reporter);


        //Assertions
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("FORGOT_VERIFY_OIDC_STATE")
                        .inClass("OidcAuthenticationRequestStateUsage")
                        .inMethod("exampleAuthenticationRequestForgetCheckState")
                        .build()
        );

        //Assertions
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("POSSIBLY_FORGOT_VERIFY_OIDC_STATE")
                        .inClass("OidcAuthenticationRequestStateUsage")
                        .inMethod("stateMatcherHandleNoMatch")
                        .build()
        );
    }
}
