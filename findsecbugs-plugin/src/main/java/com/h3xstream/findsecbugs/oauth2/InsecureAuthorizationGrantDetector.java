package com.h3xstream.findsecbugs.oauth2;

import edu.umd.cs.findbugs.BugInstance;
import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.Priorities;
import edu.umd.cs.findbugs.bcel.OpcodeStackDetector;
import org.apache.bcel.Const;

public class InsecureAuthorizationGrantDetector extends OpcodeStackDetector {
    private static final String USING_PASSWORD_GRANT_OAUTH = "USING_PASSWORD_GRANT_OAUTH";

    private BugReporter bugReporter;

    public InsecureAuthorizationGrantDetector(BugReporter bugReporter) {
        this.bugReporter = bugReporter;
    }

    @Override
    public void sawOpcode(int seen) {

        if (seen == Const.INVOKESPECIAL &&
            getClassConstantOperand().equals("com/nimbusds/oauth2/sdk/ResourceOwnerPasswordCredentialsGrant")) { // TODO: extent to other API, the google api client
            bugReporter.reportBug(new BugInstance(this, USING_PASSWORD_GRANT_OAUTH, Priorities.LOW_PRIORITY) //
                    .addClass(this).addMethod(this).addSourceLine(this));
        }
    }
}
