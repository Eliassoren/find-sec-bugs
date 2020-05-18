/**
 * Find Security Bugs
 * Copyright (c) Philippe Arteau, All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 */
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
