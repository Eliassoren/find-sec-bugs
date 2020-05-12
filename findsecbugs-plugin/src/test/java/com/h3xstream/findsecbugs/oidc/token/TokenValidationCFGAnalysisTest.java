package com.h3xstream.findsecbugs.oidc.token;

import com.h3xstream.findbugs.test.BaseDetectorTest;
import com.h3xstream.findbugs.test.EasyBugReporter;
import org.testng.annotations.Test;

import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

public class TokenValidationCFGAnalysisTest extends BaseDetectorTest {
    @Test
    public void printCFG() throws Exception {
        //Locate test code
        String[] files = {
              getClassFilePath("testcode/oidc/googleapiclient/OidcValidateTokensGoogle"),
               // getClassFilePath("testcode/oidc/otherexamples/SimpleCFG")
        };

        //Run the analysis
        EasyBugReporter reporter = spy(new BaseDetectorTest.SecurityReporter());
        analyze(files, reporter);
    }
}

