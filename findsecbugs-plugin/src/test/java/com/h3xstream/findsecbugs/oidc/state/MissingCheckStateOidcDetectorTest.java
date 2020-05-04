package com.h3xstream.findsecbugs.oidc.state;

import com.h3xstream.findbugs.test.BaseDetectorTest;
import com.h3xstream.findbugs.test.EasyBugReporter;
import org.testng.annotations.Test;

import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

public class MissingCheckStateOidcDetectorTest extends BaseDetectorTest {
    /*New bug MISSING_VERIFY_OIDC_STATE [OidcCallbackVerifyStateNimbus.callBackMissingCheckState() at 115]
|INFO | EasyBugReporter : New bug MISSING_VERIFY_OIDC_STATE [OidcCallbackVerifyStateNimbus.callBackMissingCheckStatePassedParam() at 144]
|INFO | EasyBugReporter : New bug MISSING_VERIFY_OIDC_STATE [OidcCallbackVerifyStateNimbus.stateMatcherHandleNoMatch() at 305]
|INFO | EasyBugReporter : New bug EXTERNAL_CALL_POSSIBLY_MISSING_VERIFY_OIDC_STATE [OidcCallbackVerifyStateNimbus.callBackMissingCheckStatePassedParamForeign() at 174]
|INFO | EasyBugReporter : New bug MISSING_VERIFY_OIDC_STATE [OidcCallbackVerifyStateGoogle.callbackMissingCheckState() at 305]
|INFO | EasyBugReporter : New bug MISSING_VERIFY_OIDC_STATE [OidcCallbackVerifyStateGoogle.callbackMissingCheckStatePassedToOther() at 334]
|INFO | EasyBugReporter : New bug MISSING_VERIFY_OIDC_STATE [OidcCallbackVerifyStateGoogle.passStateNoCheck() at 328]
|INFO | EasyBugReporter : New bug EXTERNAL_CALL_POSSIBLY_MISSING_VERIFY_OIDC_STATE [OidcCallbackVerifyStateGoogle.callbackMissingCheckStatePassedForeign() at 360]
*/

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
