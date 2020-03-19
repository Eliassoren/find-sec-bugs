package testcode.authclient;

import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.util.StringUtils;

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


    public static void passwordPossiblyNotErased() {
        Secret password = new Secret("foo");
        if (randomCase()) {
            return; // Secret is now in cache and not deleted yet
        }
        else if(StringUtils.isBlank(password.getValue())) { // Usage of variable. Otherwise this triggers varianle not used (Dead local storage)
            return;
        }
        password.erase();
    }

    public static void OK_passwordPossiblyNotErased() {
        Secret password = new Secret("foo");
        if (randomCase()) {
            password.erase();
            // Other operations
            return;
        }
        else if(StringUtils.isBlank(password.getValue())) { // Usage of variable
            password.erase();
            // Other operations
            return;
        }
        password.erase();
    }

    public static boolean randomCase() {
        return secureRandomGenerator.nextInt() > 0.5;
    }


    public static void OK_passwordPossiblyNotErasedBecauseOfCheckedException_1() {
        Secret password = new Secret("foo");
        try {
            randomlyThrowCheckedException();
            //throw new NullPointerException("EE");
        } catch (Exception e) {
            // log error
        } finally {
            password.erase();
        }
    }


    public static void passwordPossiblyNotErasedBecauseOfCheckedException() {
        try {
            Secret password = new Secret("foo");
            randomlyThrowCheckedException();
            password.erase();
        } catch (Exception e){
            throw new RuntimeException(e);
        }
    }

    public static void OK_passwordPossiblyNotErasedBecauseOfException_1() {
        Secret password = new Secret("foo");
        try {
            randomlyThrowException();
        } catch (Exception e) {
            // log errors
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

    private static void randomlyThrowCheckedException() throws Exception {
        int a = 2*5;
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
