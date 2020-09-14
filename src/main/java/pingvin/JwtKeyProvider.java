package pingvin;

import lombok.Getter;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;
import pingvin.tokenposition.Config;

import java.net.URL;
import java.util.*;

@UtilityClass
public class JwtKeyProvider {

    @Getter
    private static Map<URL, Integer> secrets;
    @Getter
    private static Set<String> keys;

    @SneakyThrows
    public static void loadKeys() {
        secrets = new HashMap<>();
        keys = new HashSet<>();
        for (String secret : Config.secrets) {
            final Set<String> tempKeys = new HashSet<>();
            final URL url = new URL(secret);
            final Scanner sc = new Scanner(url.openStream());

            while (sc.hasNextLine()) {
                tempKeys.add(sc.nextLine());
            }
            secrets.put(url, tempKeys.size());
            keys.addAll(tempKeys);
        }
    }

}
