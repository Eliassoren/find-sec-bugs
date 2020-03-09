package testcode.authclient;

import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.util.StringUtils;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

public class RandomTestCases {

    static SecureRandom secureRandomGenerator;

    static {
        try {
            secureRandomGenerator = SecureRandom.getInstance("SHA1PRNG", "SUN");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
    }


    public static boolean randomCase() {
        return secureRandomGenerator.nextInt() > 0.5;
    }

    private static int createStatusCode() {
        return (405)*secureRandomGenerator.nextInt();
    }
}
