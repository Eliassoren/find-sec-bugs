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
package com.h3xstream.findsecbugs.oidc.data;

import org.apache.bcel.classfile.Method;

public class AnalyzedMethodPeepholes {
    public final Method method;
    public final boolean foundContextWithParamToVerify;
    public final boolean foundParamVerify;
    public final boolean foundParamPassedToPossibleCheck;
    public final boolean foundGetParam;
    public final boolean calledMethodNameIndicatesVerify;
    public final boolean notClearedAndPossiblyPassesCheck;
    public AnalyzedMethodPeepholes(Method method,
                                   boolean foundContextWithParamToVerify,
                                   boolean foundParamVerify,
                                   boolean foundParamPassedToPossibleCheck,
                                   boolean foundGetParam,
                                   boolean calledMethodNameIndicatesVerify) {
        this.method = method;
        this.foundContextWithParamToVerify = foundContextWithParamToVerify;
        this.foundParamVerify = foundParamVerify;
        this.foundParamPassedToPossibleCheck = foundParamPassedToPossibleCheck;
        this.foundGetParam = foundGetParam;
        this.calledMethodNameIndicatesVerify = calledMethodNameIndicatesVerify;
        notClearedAndPossiblyPassesCheck = foundContextWithParamToVerify
                                            && !foundParamVerify
                                            && foundParamPassedToPossibleCheck
                                            && !calledMethodNameIndicatesVerify;
    }
}

