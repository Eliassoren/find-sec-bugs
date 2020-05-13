package com.h3xstream.findsecbugs.oidc.data.cfg;

import edu.umd.cs.findbugs.ba.BasicBlock;

import java.util.ArrayList;
import java.util.List;

public class ReturnBlockTrail {
    private final BasicBlock parentWithTokenVerify;
    private List<BasicBlock> trail;
    private boolean foundReturnStatement;
    private boolean foundHttpResponseStatus;
    private boolean foundResponseIndicatingInvalidation;
    public ReturnBlockTrail(BasicBlock parentWithTokenVerify) {
        this.parentWithTokenVerify = parentWithTokenVerify;
        trail = new ArrayList<>();
        trail.add(parentWithTokenVerify);
        foundReturnStatement = false;
        foundHttpResponseStatus = false;
        foundResponseIndicatingInvalidation = false;
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

    public boolean foundResponseIndicationInvalidation() {
        return foundResponseIndicatingInvalidation;
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

    public void setFoundResponseIndicatingInvalidation(boolean foundResponseIndicatingInvalidation) {
        this.foundResponseIndicatingInvalidation = foundResponseIndicatingInvalidation;
    }
}
