package testcode.rest;

import com.nimbusds.oauth2.sdk.auth.Secret;

public class AuthTestCases {
    public static int easy1() {
        return 42;
    }

    public static double detectMathRandom() {
        return Math.random();
    }

    public static void passwordPossiblyNotErased() {
        Secret password = new Secret("foo");
        if (randomChoice()) {
            return;
        }
        password.erase();
    }

    private static boolean randomChoice() {
        return Math.random() > 0.5;
    }

    public static void passwordPossiblyNotErasedBecauseOfException() {
        Secret password = new Secret("foo");
        randomlyThrowException();
        password.erase();
    }

    public static void OK_passwordPossiblyNotErasedBecauseOfException_1() {
        Secret password = new Secret("foo");
        try {
            randomlyThrowException();
        } finally {
            password.erase();
        }
    }

    public static void OK_passwordPossiblyNotErasedBecauseOfException_2() {
        Secret password = null;
        try {
            password = new Secret("foo");
            randomlyThrowException();
        } finally {
            if(password != null) {
                password.erase();
            }
        }
    }

    private static void randomlyThrowException() {
        throw new RuntimeException();
    }

    public static void notStrongEnoughtStatusCodeChecking() {
        int statusCode = createRandomStatusCode();
        if (statusCode == 401 || statusCode == 402) {
            throw new RuntimeException();
        }

    }

    private static int createRandomStatusCode() {
        return (int) (4242 * Math.random());
    }
}
