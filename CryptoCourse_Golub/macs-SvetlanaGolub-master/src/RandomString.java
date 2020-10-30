public class RandomString {


    static String getAlphaNumericString(int n) {

        StringBuilder sb = new StringBuilder(n);

        for (int i = 0; i < n; i++) {
            String alphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "0123456789" + "abcdefghijklmnopqrstuvxyz";
            int index = (int) (alphaNumericString.length() * Math.random());
            sb.append(alphaNumericString.charAt(index));
        }
        return sb.toString();
    }

}
