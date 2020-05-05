package com.h3xstream.findsecbugs.oidc.badpractice;

import edu.umd.cs.findbugs.BugInstance;
import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.Priorities;
import edu.umd.cs.findbugs.bcel.OpcodeStackDetector;
import org.apache.bcel.Const;

import java.util.Arrays;
import java.util.List;

public class InsecureAuthorizationGrantDetector extends OpcodeStackDetector {
    private static final String USING_PASSWORD_GRANT_OAUTH = "USING_PASSWORD_GRANT_OAUTH";

    private BugReporter bugReporter;
    private final String PASSWORD_GRANT_GOOGLE_API_SDK = "com/google/api/client/auth/oauth2/PasswordTokenRequest"; // Todo write test code
    private final String PASSWORD_GRANT_NIMBUS_SDK = "com/nimbusds/oauth2/sdk/ResourceOwnerPasswordCredentialsGrant";
    private final List<String> PASSWORD_GRANT = Arrays.asList(PASSWORD_GRANT_NIMBUS_SDK,
                                                PASSWORD_GRANT_GOOGLE_API_SDK);

    public InsecureAuthorizationGrantDetector(BugReporter bugReporter) {
        this.bugReporter = bugReporter;
    }

    @Override
    public void sawOpcode(int seen) {
        if (seen == Const.INVOKESPECIAL &&
                (PASSWORD_GRANT
                        .stream()
                        .anyMatch(s -> s.equals(getClassConstantOperand())))) {
            bugReporter.reportBug(new BugInstance(this, USING_PASSWORD_GRANT_OAUTH, Priorities.NORMAL_PRIORITY) //
                    .addClass(this).addMethod(this).addSourceLine(this));
        }
    }
}
