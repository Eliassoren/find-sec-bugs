package com.h3xstream.findsecbugs.oidc.state;

import com.h3xstream.findbugs.test.BaseDetectorTest;
import com.h3xstream.findbugs.test.EasyBugReporter;
import org.testng.annotations.Test;

import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

public class MissingCheckStateOidcDetectorTest extends BaseDetectorTest {
    /*New bug MISSING_VERIFY_OIDC_STATE [OidcAuthFlowStateUsageRedirect.callBackMissingCheckState() at 115]
|INFO | EasyBugReporter : New bug MISSING_VERIFY_OIDC_STATE [OidcAuthFlowStateUsageRedirect.callBackMissingCheckStatePassedParam() at 144]
|INFO | EasyBugReporter : New bug MISSING_VERIFY_OIDC_STATE [OidcAuthFlowStateUsageRedirect.stateMatcherHandleNoMatch() at 305]
|INFO | EasyBugReporter : New bug EXTERNAL_CALL_POSSIBLY_MISSING_VERIFY_OIDC_STATE [OidcAuthFlowStateUsageRedirect.callBackMissingCheckStatePassedParamForeign() at 174]
|INFO | EasyBugReporter : New bug MISSING_VERIFY_OIDC_STATE [OidcAuthFlowStateUsageGoogle.callbackMissingCheckState() at 305]
|INFO | EasyBugReporter : New bug MISSING_VERIFY_OIDC_STATE [OidcAuthFlowStateUsageGoogle.callbackMissingCheckStatePassedToOther() at 334]
|INFO | EasyBugReporter : New bug MISSING_VERIFY_OIDC_STATE [OidcAuthFlowStateUsageGoogle.passStateNoCheck() at 328]
|INFO | EasyBugReporter : New bug EXTERNAL_CALL_POSSIBLY_MISSING_VERIFY_OIDC_STATE [OidcAuthFlowStateUsageGoogle.callbackMissingCheckStatePassedForeign() at 360]
*/

    @Test
    public void forgotToCheckStateTestNimbusSDK() throws Exception {
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
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("MISSING_VERIFY_OIDC_STATE")
                        .inClass("OidcAuthFlowStateUsageRedirect")
                        .inMethod("callBackMissingCheckStatePassedParam")
                        .build()
        );
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("MISSING_VERIFY_OIDC_STATE")
                        .inClass("OidcAuthFlowStateUsageRedirect")
                        .inMethod("stateMatcherHandleNoMatch")
                        .build()
        );
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("EXTERNAL_CALL_POSSIBLY_MISSING_VERIFY_OIDC_STATE")
                        .inClass("OidcAuthFlowStateUsageRedirect")
                        .inMethod("callBackMissingCheckStatePassedParamForeign")
                        .build()
        );



    }

    @Test
    public void forgotToCheckStateTestGoogleSDK() throws Exception {
        //Locate test code
        String[] files = {
                getClassFilePath("testcode/oidc/googleapiclient/OidcAuthFlowStateUsageGoogle")
        };

        //Run the analysis
        EasyBugReporter reporter = spy(new BaseDetectorTest.SecurityReporter());
        analyze(files, reporter);

        //Assertions
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("MISSING_VERIFY_OIDC_STATE")
                        .inClass("OidcAuthFlowStateUsageGoogle")
                        .inMethod("callbackMissingCheckState")
                        .build()
        );
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("MISSING_VERIFY_OIDC_STATE")
                        .inClass("OidcAuthFlowStateUsageGoogle")
                        .inMethod("callbackMissingCheckStatePassedToOther")
                        .build()
        );
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("MISSING_VERIFY_OIDC_STATE")
                        .inClass("OidcAuthFlowStateUsageGoogle")
                        .inMethod("passStateNoCheck")
                        .build()
        );
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("EXTERNAL_CALL_POSSIBLY_MISSING_VERIFY_OIDC_STATE")
                        .inClass("OidcAuthFlowStateUsageGoogle")
                        .inMethod("callbackMissingCheckStatePassedForeign")
                        .build()
        );
    }
}
