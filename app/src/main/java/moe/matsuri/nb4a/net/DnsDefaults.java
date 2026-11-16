package moe.matsuri.nb4a.net;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/** One-way migration of removed legacy DNS defaults. Endpoint addresses are
 * absent from the shipped APK; fingerprints only recognize existing settings. */
public final class DnsDefaults {
    private static final String GOOGLE = "https://dns.google/dns-query";
    private static final Set<String> RETIRED = new HashSet<>(Arrays.asList(
            "9a069c7221535d677f9e302f0a958c77cdb3bef17ac7db0724220d6d0c165665",
            "3b2208cd59ef69982da19214ea3c41708d6da080524867212dd6a94c9106d0b8",
            "5fe8e293dec28c536bfbc36bb0799957bc6a458db294bd2b7ee2700eaf2eda19",
            "e198702839426ad90af8c227c1069c297aafca0e1e707ee2ad52d54c8c30c414",
            "fe9baa4975c0bc9a065ca294f75311ea8c1d504cd84923c4419af713318c8155",
            "7f8bbd258cb0af5901376522b825a154db0f2e4c3f1af9dd7520d2474590fb87",
            "33a13277966e66e3e68dd0d957d466084c630b782665b92c52632e4f7aab78cd",
            "53a333e3c2a80a6bc7f5a5ccf55b8b719e406e12f51d9d686e249f863337c532",
            "6cacd60254abbf79c6417f56b8ce2142da7ae26835b9eeda252329fe4fb369f7",
            "34b9bab39b8a9d8d76671aa1f41e66d67d1b911735e687d81655c0bf404eb8da",
            "f69124aa768297d1a8fa871c463a7df13b4ce79603ea68da0853c8af99e35938"));

    private DnsDefaults() {}

    public static String migrate(String value) {
        String[] lines = value.split("\n", -1);
        boolean changed = false;
        for (int i = 0; i < lines.length; i++) {
            if (RETIRED.contains(sha256(lines[i].trim()))) {
                lines[i] = GOOGLE;
                changed = true;
            }
        }
        if (!changed) return value;
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < lines.length; i++) {
            if (i > 0) result.append('\n');
            result.append(lines[i]);
        }
        return result.toString();
    }

    private static String sha256(String value) {
        try {
            byte[] bytes = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            char[] hex = "0123456789abcdef".toCharArray();
            StringBuilder out = new StringBuilder(64);
            for (byte b : bytes) out.append(hex[(b & 255) >>> 4]).append(hex[b & 15]);
            return out.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
