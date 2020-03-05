package testcode.authclient;

import com.nimbusds.oauth2.sdk.auth.Secret;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

public class AuthTestCases {

    static SecureRandom secureRandomGenerator;

    static {
        try {
            secureRandomGenerator = SecureRandom.getInstance("SHA1PRNG", "SUN");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
    }


    public static int easy1() {
        return 42;
    }

    public static void passwordPossiblyNotErased() {
        Secret password = new Secret("foo");
        if (randomCase()) {
            return;
        }
        password.erase();
    }

    private static boolean randomCase() {
        return secureRandomGenerator.nextInt() > 0.5;
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
        int statusCode = createStatusCode();
        if (statusCode == 401 || statusCode == 402) {
            throw new RuntimeException();
        }

    }

    private static int createStatusCode() {
        return (405)*secureRandomGenerator.nextInt();
    }
}
