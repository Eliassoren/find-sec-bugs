package com.h3xstream.findsecbugs.oidc;

import com.h3xstream.findbugs.test.BaseDetectorTest;
import com.h3xstream.findbugs.test.EasyBugReporter;
import org.testng.annotations.Test;

import static org.mockito.Mockito.*;


public class InsecureDeleteSecretTest extends BaseDetectorTest {


    @Test
    public void unsafeDeleteSecretTest() throws Exception {
        //Locate test code
        String[] files = {
                getClassFilePath("testcode/oidc/nimbus/badpractice/InsecureDeleteSecret")
        };

        //Run the analysis
        EasyBugReporter reporter = spy(new SecurityReporter());
        analyze(files, reporter);


        //Assertions
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("UNSAFE_DELETE_SECRET_AUTH")
                        .inClass("InsecureDeleteSecret")
                        .inMethod("secretPossiblyNotErased")
                        .build()
        );

        //Assertions
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("UNSAFE_DELETE_SECRET_AUTH_EXCEPTION_PATH")
                        .inClass("InsecureDeleteSecret")
                        .inMethod("secretPossiblyNotErasedBecauseOfCheckedException")
                        .build()
        );

        //Assertions
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("UNSAFE_DELETE_SECRET_AUTH_EXCEPTION_PATH")
                        .inClass("InsecureDeleteSecret")
                        .inMethod("secretPossiblyNotErasedBecauseOfCheckedException")
                        .build()
        );

        //Assertions
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("UNSAFE_DELETE_SECRET_AUTH_EXCEPTION_PATH")
                        .inClass("InsecureDeleteSecret")
                        .inMethod("secretPossiblyNotErasedBecauseOfExceptionAndConditional")
                        .build()
        );

         //Assertions
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("UNSAFE_DELETE_SECRET_AUTH_EXCEPTION_PATH")
                        .inClass("InsecureDeleteSecret")
                        .inMethod("secretPossiblyNotErasedExceptionNaiveNoTry")
                        .build()
        );



    }



}
