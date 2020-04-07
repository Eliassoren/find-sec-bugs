package com.h3xstream.findsecbugs.oauth2.data;

import org.apache.bcel.classfile.Method;

public class AnalyzedMethod {
    public final Method method;
    public final boolean foundAuthContext;
    public final boolean foundStateVerify;
    public final boolean foundStatePassedAsParamToPossibleCheck;

    public AnalyzedMethod(Method method, boolean foundAuthContext, boolean foundStateVerify, boolean foundStatePassedAsParamToPossibleCheck) {
        this.method = method;
        this.foundAuthContext = foundAuthContext;
        this.foundStateVerify = foundStateVerify;
        this.foundStatePassedAsParamToPossibleCheck = foundStatePassedAsParamToPossibleCheck;
    }
}
