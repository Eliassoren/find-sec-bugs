package com.h3xstream.findsecbugs.oidc.authorizationcodeflow;

import com.h3xstream.findbugs.test.BaseDetectorTest;
import com.h3xstream.findbugs.test.EasyBugReporter;
import org.testng.annotations.Test;

import static org.mockito.Mockito.spy;

public class EvaluationOpenSourceCode extends BaseDetectorTest {

    @Test
    public void zopAppEvalTest() throws Exception {
        //Locate test code
        String[] files = {
                getClassFilePath("testcode/oidc/gitignore/evaluation/OIDCUtils")
        };

        //Run the analysis
        EasyBugReporter reporter = spy(new BaseDetectorTest.SecurityReporter());
        analyze(files, reporter);
    }
}
