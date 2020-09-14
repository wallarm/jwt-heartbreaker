package pingvin.tokenposition;

import com.eclipsesource.json.*;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Config {

    public static PrintWriter stdout;
    public static PrintWriter stderr;

    private static JsonObject configJO;

    public static List<String> jwtKeywords = Arrays.asList("Authorization: Bearer", "Authorization: bearer", "authorization: Bearer", "authorization: bearer");
    public static List<String> tokenKeywords = Arrays.asList("id_token", "ID_TOKEN", "access_token", "token");
    public static List<String> secrets = Arrays.asList("https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list");

    public static String configName = "config.json";
    public static String configFolderName = ".JWTheartbreaker";
    public static String configPath = System.getProperty("user.home") + File.separator + configFolderName + File.separator + configName;

    public static void loadConfig() {
        File configFile = new File(configPath);

        if (!configFile.getParentFile().exists()) {
            Output.output("Config file directory '" + configFolderName + "' does not exist - creating it");
            configFile.getParentFile().mkdir();
        }

        if (!configFile.exists()) {
            Output.output("Config file '" + configPath + "' does not exist - creating it");
            try {
                configFile.createNewFile();
            } catch (IOException e) {
                Output.outputError("Error creating config file '" + configPath + "' - message:" + e.getMessage() + " - cause:" + e.getCause().toString());
                return;
            }
            String defaultConfigJSONRaw = generateDefaultConfigFile();
            try {
                Files.write(Paths.get(configPath), defaultConfigJSONRaw.getBytes());
            } catch (IOException e) {
                Output.outputError("Error writing config file '" + configPath + "' - message:" + e.getMessage() + " - cause:" + e.getCause().toString());
            }
        }

        try {
            String configRaw = new String(Files.readAllBytes(Paths.get(configPath)));
            configJO = Json.parse(configRaw).asObject();

            JsonArray secretsJA = configJO.get("secrets").asArray();
            secrets = new ArrayList<>();
            for (JsonValue jsonValue : secretsJA) {
                secrets.add(jsonValue.asString());
            }

            JsonArray jwtKeywordsJA = configJO.get("jwtKeywords").asArray();
            jwtKeywords = new ArrayList<String>();
            for (JsonValue jwtKeyword : jwtKeywordsJA) {
                jwtKeywords.add(jwtKeyword.asString());
            }

            JsonArray tokenKeywordsJA = configJO.get("tokenKeywords").asArray();
            tokenKeywords = new ArrayList<String>();
            for (JsonValue tokenKeyword : tokenKeywordsJA) {
                tokenKeywords.add(tokenKeyword.asString());
            }

        } catch (IOException e) {
            Output.outputError("Error loading config file '" + configPath + "' - message:" + e.getMessage() + " - cause:" + e.getCause().toString());
        }
    }

    private static String generateDefaultConfigFile() {
        configJO = new JsonObject();

        JsonArray secretsJA = new JsonArray();
        for (String secret : secrets) {
            secretsJA.add(secret);
        }

        JsonArray jwtKeywordsJA = new JsonArray();
        for (String jwtKeyword : jwtKeywords) {
            jwtKeywordsJA.add(jwtKeyword);
        }

        JsonArray tokenKeywordsJA = new JsonArray();
        for (String tokenKeyword : tokenKeywords) {
            tokenKeywordsJA.add(tokenKeyword);
        }

        configJO.add("secrets", secretsJA);
        configJO.add("jwtKeywords", jwtKeywordsJA);
        configJO.add("tokenKeywords", tokenKeywordsJA);

        return configJO.toString(WriterConfig.PRETTY_PRINT);
    }

    public static void updateSecrets(List<String> secrets) {
        JsonArray secretsJA = new JsonArray();
        for (String secret : secrets) {
            secretsJA.add(secret);
        }

        configJO.set("secrets", secretsJA);

        try {
            Files.write(Paths.get(configPath), configJO.toString(WriterConfig.PRETTY_PRINT).getBytes());
        } catch (IOException e) {
            Output.outputError("Error writing config file '" + configPath + "' - message:" + e.getMessage() + " - cause:" + e.getCause().toString());
        }
    }
}
