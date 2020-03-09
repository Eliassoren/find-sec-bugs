package com.h3xstream.findsecbugs.authclient;

import com.h3xstream.findbugs.test.BaseDetectorTest;
import com.h3xstream.findbugs.test.EasyBugReporter;
import org.testng.annotations.Test;

import static org.mockito.Mockito.*;


public class AuthTestCasesTest extends BaseDetectorTest {

    @Test
    public void simpleDetectionTest() throws Exception {
        /*
        * Temporary sanity test to make sure that detection works properly. Remove after impl
        * */

        //Locate test code
        String[] files = {
                getClassFilePath("testcode/authclient/RandomTestCases")
        };

        //Run the analysis
        EasyBugReporter reporter = spy(new SecurityReporter());
        analyze(files, reporter);


        //Assertions
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("TEST_USING_SECURE_RANDOM")
                        .inClass("RandomTestCases")
                        .inMethod("randomCase")
                        .build()
        );

        //Assertions
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("TEST_USING_SECURE_RANDOM")
                        .inClass("RandomTestCases")
                        .inMethod("createStatusCode")
                        .build()
        );
        //Assertions
        verify(reporter, times(2)).doReportBug(
                bugDefinition()
                        .bugType("TEST_USING_SECURE_RANDOM")
                        .build()
        );

    }

    @Test
    public void unsafeDeletionOfSecretTest() throws Exception {
        //Locate test code
        String[] files = {
                getClassFilePath("testcode/authclient/AuthTestCases")
        };

        //Run the analysis
        EasyBugReporter reporter = spy(new SecurityReporter());
        analyze(files, reporter);


        //Assertions
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("UNSAFE_DELETE_SECRET_AUTH")
                        .inClass("AuthTestCases")
                        .inMethod("passwordPossiblyNotErased")
                        .build()
        );

        //Assertions
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("UNSAFE_DELETE_SECRET_AUTH_EXCEPTION_PATH")
                        .inClass("AuthTestCases")
                        .inMethod("passwordPossiblyNotErasedBecauseOfException")
                        .build()
        );
    }
}
