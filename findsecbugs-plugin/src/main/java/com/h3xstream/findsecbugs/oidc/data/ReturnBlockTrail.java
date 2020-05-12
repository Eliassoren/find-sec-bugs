package com.h3xstream.findsecbugs.oidc.data;

import edu.umd.cs.findbugs.ba.BasicBlock;
import org.apache.bcel.Const;
import org.apache.bcel.generic.GETSTATIC;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.StreamSupport;

public class ReturnBlockTrail {
    private final BasicBlock parentWithTokenVerify;
    private List<BasicBlock> trail;
    private boolean foundReturnStatement;
    private boolean foundHttpResponseStatus;
    private boolean foundHttp400sCode;
    public ReturnBlockTrail(BasicBlock parentWithTokenVerify) {
        this.parentWithTokenVerify = parentWithTokenVerify;
        trail = new ArrayList<>();
        trail.add(parentWithTokenVerify);
        foundReturnStatement = false;
        foundHttpResponseStatus = false;
        foundHttp400sCode = false;
    }

    public BasicBlock getParentWithTokenVerify() {
        return parentWithTokenVerify;
    }

    public boolean foundReturnStatement() {
        return foundReturnStatement;
    }

    public boolean foundHttpResponseStatus() {
        return foundHttpResponseStatus;
    }

    public boolean foundHttp400sCode() {
        return foundHttp400sCode;
    }

    public void addBlockToTrail(BasicBlock basicBlock) {
        trail.add(basicBlock);
    }

    public void setFoundReturnStatement(boolean foundReturnStatement) {
        this.foundReturnStatement = foundReturnStatement;
    }

    public void setFoundHttpResponseStatus(boolean foundHttpResponseStatus) {
        this.foundHttpResponseStatus = foundHttpResponseStatus;
    }

    public void setFoundHttp400sCode(boolean foundHttp400sCode) {
        this.foundHttp400sCode = foundHttp400sCode;
    }
}
