package com.h3xstream.findsecbugs.authclient;

import com.h3xstream.findbugs.test.BaseDetectorTest;
import com.h3xstream.findbugs.test.EasyBugReporter;
import org.testng.annotations.Test;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;



public class AuthTestCasesTest extends BaseDetectorTest {

    @Test
    public void simpleDetectionTest() throws Exception {
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
                        .bugType("AUTHCLIENT_TEST_RANDOMNUMBER")
                        .inClass("AuthTestCases")
                        .inMethod("randomCase")
                        .build()
        );


    }
}
