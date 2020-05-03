package testcode.oidc.googleapiclient;

public class ForeignPassMethodUtil {
    public static void passStateNoCheck(String state) {
        int a = state.compareTo("randomstrin");
    }
}
