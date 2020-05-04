package com.h3xstream.findsecbugs.oidc.data;

import org.apache.bcel.classfile.Method;

public class AnalyzedMethodStateUsage {
    public final Method method;
    public final boolean foundAuthContextWithState;
    public final boolean foundStateVerify;
    public final boolean foundStatePassedAsParamToPossibleCheck;
    public final boolean foundGetState;
    public final boolean calledMethodContainsStateInName;
    public final boolean notClearedAndPossiblyPassesCheck;
    public AnalyzedMethodStateUsage(Method method,
                                    boolean foundAuthContextWithState,
                                    boolean foundStateVerify,
                                    boolean foundStatePassedAsParamToPossibleCheck,
                                    boolean foundGetState,
                                    boolean calledMethodContainsStateInName) {
        this.method = method;
        this.foundAuthContextWithState = foundAuthContextWithState;
        this.foundStateVerify = foundStateVerify;
        this.foundStatePassedAsParamToPossibleCheck = foundStatePassedAsParamToPossibleCheck;
        this.foundGetState = foundGetState;
        this.calledMethodContainsStateInName = calledMethodContainsStateInName;
        notClearedAndPossiblyPassesCheck = foundAuthContextWithState && !foundStateVerify && foundStatePassedAsParamToPossibleCheck;
    }
}

