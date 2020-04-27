package com.h3xstream.findsecbugs.oidc.state;

import com.h3xstream.findbugs.test.BaseDetectorTest;
import com.h3xstream.findbugs.test.EasyBugReporter;
import org.testng.annotations.Test;

import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

public class MissingCheckStateOidcDetectorTest extends BaseDetectorTest {
    @Test
    public void forgotToCheckStateTest() throws Exception {
        //Locate test code
        String[] files = {
                getClassFilePath("testcode/oidc/nimbus/OidcAuthFlowStateUsageRedirect")
        };

        //Run the analysis
        EasyBugReporter reporter = spy(new BaseDetectorTest.SecurityReporter());
        analyze(files, reporter);


        //Assertions
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("MISSING_VERIFY_OIDC_STATE")
                        .inClass("OidcAuthFlowStateUsageRedirect")
                        .inMethod("callBackMissingCheckState")
                        .build()
        );

    }
}
