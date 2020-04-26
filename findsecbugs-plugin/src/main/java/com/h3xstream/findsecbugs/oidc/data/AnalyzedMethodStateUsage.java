package com.h3xstream.findsecbugs.oidc.data;

import org.apache.bcel.classfile.Method;

public class AnalyzedMethodStateUsage {
    public final Method method;
    public final boolean foundAuthContextWithState;
    public final boolean foundStateVerify;
    public final boolean foundStatePassedAsParamToPossibleCheck;

    public AnalyzedMethodStateUsage(Method method, boolean foundAuthContextWithState, boolean foundStateVerify, boolean foundStatePassedAsParamToPossibleCheck) {
        this.method = method;
        this.foundAuthContextWithState = foundAuthContextWithState;
        this.foundStateVerify = foundStateVerify;
        this.foundStatePassedAsParamToPossibleCheck = foundStatePassedAsParamToPossibleCheck;
    }
}
