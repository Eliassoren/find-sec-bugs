package com.h3xstream.findsecbugs.oidc.data;

public class CalledMethodIdentifiers {
    public final String className;
    public final String methodName;
    public final String methodSig;

    public CalledMethodIdentifiers(String className, String methodName, String methodSig) {
        this.className = className;
        this.methodName = methodName;
        this.methodSig = methodSig;
    }

    @Override
    public String toString() {
        return "Called Method {" +
                "Class Name= ' " + className + '\'' +
                ", Method Name = ' " + methodName + '\'' +
                ", Method Signature = ' " + methodSig + '\'' +
                '}';
    }
}
