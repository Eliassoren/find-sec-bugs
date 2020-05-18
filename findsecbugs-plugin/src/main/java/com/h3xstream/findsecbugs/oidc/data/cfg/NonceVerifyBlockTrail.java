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

public class NonceVerifyBlockTrail {
    private final BasicBlock lastChildWithIfConditional;
    private List<BasicBlock> trail;
    private boolean foundStringEquals;
    private boolean foundGetNonce;
    public NonceVerifyBlockTrail(BasicBlock lastChildWithIfConditional) {
        this.lastChildWithIfConditional = lastChildWithIfConditional;
        trail = new ArrayList<>();
        trail.add(lastChildWithIfConditional);
        foundStringEquals = false;
        foundGetNonce = false;
    }

    public BasicBlock getLastChildWithIfConditional() {
        return lastChildWithIfConditional;
    }

    public List<BasicBlock> getTrail() {
        return trail;
    }

    public void addBlockToTrail(BasicBlock b) {
        trail.add(b);
    }

    public void setTrail(List<BasicBlock> trail) {
        this.trail = trail;
    }

    public boolean foundStringEquals() {
        return foundStringEquals;
    }

    public void setFoundStringEquals(boolean foundStringEquals) {
        this.foundStringEquals = foundStringEquals;
    }

    public boolean foundGetNonce() {
        return foundGetNonce;
    }

    public void setFoundGetNonce(boolean foundGetNonce) {
        this.foundGetNonce = foundGetNonce;
    }
}
