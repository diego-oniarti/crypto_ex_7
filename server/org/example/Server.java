package org.example;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * A server exposing 3 endpoints, 1 for showing public
 * debug info and 2 for en/decrypting with RSA.
 */
public class Server {

    public final int KEY_BITS = 1024;
    public final int PORT = 8000;
    public final RSAPKCS1 rsa = new RSAPKCS1(KEY_BITS);


    /** Start the server and log some output */
    public void startServer() throws IOException {
        System.out.println("Server starting on port " + PORT);
        System.out.println("APIs: ");
        System.out.println(" - GET /");
        System.out.println(" - GET /encrypt?p=<hex plaintext>&r=<repeats (optional, default 1)>");
        System.out.println(" - GET /decrypt?c=<hex ciphertext>&r=<repeats (optional, default 1)>");

        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        server.createContext("/", new RootHandler());
        server.createContext("/encrypt", new EncryptHandler());
        server.createContext("/decrypt", new DecryptHandler());
        server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
        server.start();
    }


    /** Handler for the "/" API, showing public debug information. */
    class RootHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            System.out.println("API was invoked: \"/\" ");
            String json = "{\n" +
                "  \"server\": \"RSA timing lab server\",\n" +
                "  \"public\": {\n" +
                "    \"public_key_size_bits\": " + KEY_BITS + ",\n" +
                "    \"public_modulus_hex\": \"" + rsa.modulus.toString(16) + "\",\n" +
                "    \"public_exponent_dec\": \"" + rsa.publicExponent.toString(10) + "\"\n" +
                "  },\n" +
                "  \"apis\": [\n" +
                "    {\n" +
                "      \"method\": \"GET\",\n" +
                "      \"path\": \"/\",\n" +
                "      \"description\": \"Return debug information (this JSON).\"\n" +
                "    },\n" +
                "    {\n" +
                "      \"method\": \"GET\",\n" +
                "      \"path\": \"/encrypt?p=<hex plaintext>&r=<repeats>\",\n" +
                "      \"description\": \"Encrypt a plaintext; optional r repeats to amplify timing (default 1, max 2000).\"\n" +
                "    },\n" +
                "    {\n" +
                "      \"method\": \"GET\",\n" +
                "      \"path\": \"/decrypt?c=<hex ciphertext>&r=<repeats>\",\n" +
                "      \"description\": \"Decrypt a ciphertext; optional r repeats to amplify timing (default 1, max 2000).\"\n" +
                "    }\n" +
                "  ]\n" +
                "}"
            ;
            writeOutput(json, 200, exchange);
        }
    }

    /** Handler for the "/encrypt" API, encrypting a given hexadecimal plaintext. */
    class EncryptHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            System.out.println("API was invoked: \"/encrypt\" ");

            // Ensure the method is a "GET".
            if (!exchange.getRequestMethod().equalsIgnoreCase("GET")) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            // Extract the "p" and "r" parameters from the URL.
            URI requri = exchange.getRequestURI();
            String query = requri.getRawQuery();
            Map<String,String> params = queryToMap(query);

            String pHex = params.get("p");
            if (pHex == null) {
                writeOutput(
                """
                    {
                      "server": "RSA timing lab server",
                      "error": "Missing 'p' (plaintext) parameter"
                    }
                    """,
                    400,
                    exchange
                );
                return;
            }
            System.out.println("API was invoked: \"/encrypt\" with plaintext " + pHex);

            int repeats = 1;
            if (params.get("r") != null) {
                try {
                    repeats = Integer.parseInt(params.get("r"));
                } catch (NumberFormatException e) {
                    writeOutput(
                    """
                        {
                          "server": "RSA timing lab server",
                          "error": "Repeat 'r' parameter was malformed"
                        }
                        """,
                        400,
                        exchange
                    );
                    return;
                }
                if (repeats < 1 || repeats > 2000) {
                    writeOutput(
                    """
                        {
                          "server": "RSA timing lab server",
                          "error": "Repeat 'r' parameter must be between 1 and 2000"
                        }
                        """,
                        400,
                        exchange
                    );
                    return;
                }
            }
            System.out.println("API was invoked: \"/encrypt\" with repeat " + repeats);

            // Convert the plaintext into a hexadecimal string.
            byte[] plaintext;
            try {
                plaintext = hexToBytes(pHex);
            } catch (Exception ex) {
                writeOutput(
                """
                    {
                      "server": "RSA timing lab server",
                      "error": "Invalid plaintext hex"
                    }
                    """,
                    400,
                    exchange
                );
                return;
            }

            // Perform repeated encryption computations to amplify timing differences.
            BigInteger result = null;
            long duration = 0;
            boolean error = false;
            for (int i = 0; i < repeats; i++) {
                long start = System.nanoTime();
                try {
                    result = rsa.encrypt(plaintext);
                } catch (Exception e) {
                    error = true;
                }
                long end = System.nanoTime();
                duration = duration + (end - start);
            }
            if (error) {
                String json = "{\n" +
                    "  \"server\": \"RSA timing lab server\",\n" +
                    "  \"error\": \"error while encrypting (invalid plaintext)\",\n" +
                    "  \"time_ns\": \"" + duration + "\"\n" +
                    "}"
                    ;
                writeOutput(json, 500, exchange);
            } else {
                // Return the encrypted message bytes as hex.
                byte[] cipherBytes = result.toByteArray();
                String cipherHex = bytesToHex(cipherBytes);
                String json = "{\n" +
                    "  \"server\": \"RSA timing lab server\",\n" +
                    "  \"cipher_hex\": \"" + cipherHex + "\",\n" +
                    "  \"time_ns\": \"" + duration + "\"\n" +
                    "}"
                ;
                writeOutput(json, 200, exchange);
            }
        }
    }

    /** Handler for the "/decrypt" API, decrypting a given hexadecimal ciphertext. */
    class DecryptHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            System.out.println("API was invoked: \"/decrypt\" ");

            // Ensure the method is a "GET".
            if (!exchange.getRequestMethod().equalsIgnoreCase("GET")) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            // Extract the "c" and "r" parameters from the URL.
            URI requri = exchange.getRequestURI();
            String query = requri.getRawQuery();
            Map<String,String> params = queryToMap(query);

            String cHex = params.get("c");
            if (cHex == null) {
                writeOutput(
                """
                    {
                      "server": "RSA timing lab server",
                      "error": "Missing 'p' (plaintext) parameter"
                    }
                    """,
                    400,
                    exchange
                );
                return;
            }
            System.out.println("API was invoked: \"/decrypt\" with ciphertext " + cHex);

            int repeats = 1;
            if (params.get("r") != null) {
                try {
                    repeats = Integer.parseInt(params.get("r"));
                } catch (NumberFormatException e) {
                    writeOutput(
                    """
                        {
                          "server": "RSA timing lab server",
                          "error": "Repeat 'r' parameter was malformed"
                        }
                        """,
                        400,
                        exchange
                    );
                    return;
                }
                if (repeats < 1 || repeats > 2000) {
                    writeOutput(
                    """
                        {
                          "server": "RSA timing lab server",
                          "error": "Repeat 'r' parameter must be between 1 and 2000"
                        }
                        """,
                        400,
                        exchange
                    );
                    return;
                }
            }
            System.out.println("API was invoked: \"/decrypt\" with repeat " + repeats);

            // Convert the ciphertext into a BigInteger.
            BigInteger ciphertext;
            try {
                ciphertext = new BigInteger(cHex, 16);
            } catch (Exception ex) {
                writeOutput(
                """
                    {
                      "server": "RSA timing lab server",
                      "error": "Invalid ciphertext hex"
                    }
                    """,
                    400,
                    exchange
                );
                return;
            }

            // Perform repeated decryption computations to amplify timing differences.
            byte[] result = null;
            long duration = 0;
            boolean error = false;
            for (int i = 0; i < repeats; i++) {
                long start = System.nanoTime();
                try {
                    result = rsa.decrypt(ciphertext);
                } catch (Exception e) {
                    error = true;
                }
                long end = System.nanoTime();
                duration = duration + (end - start);
            }
            if (error) {
                String json = "{\n" +
                    "  \"server\": \"RSA timing lab server\",\n" +
                    "  \"error\": \"error while decrypting (invalid ciphertext)\",\n" +
                    "  \"time_ns\": \"" + duration + "\"\n" +
                    "}"
                ;
                writeOutput(json, 500, exchange);
            } else {
            // Return the decrypted message bytes as hex.
            String plainHex = bytesToHex(result);
            String json = "{\n" +
                "  \"server\": \"RSA timing lab server\",\n" +
                // "  \"plain_hex\": \"" + plainHex + "\",\n" +
                "  \"time_ns\": \"" + duration + "\"\n" +
                "}"
            ;
            writeOutput(json, 200, exchange);
            }
        }
    }

    /**
     * Utility method to return an application/json as output in the given HttpExchange.
     * @param json the JSON string to return as output (UTF-8)
     * @param code the HTTP code
     * @param exchange the HttpExchange
     * @throws IOException Exception in writing the output
     */
    public void writeOutput(String json, int code, HttpExchange exchange) throws IOException {
        byte[] out = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(code, out.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(out);
        }
    }

    /**
     * Utility method to parse a query string into a map of parameters.
     * @param query the query string of the URL
     * @return the map of the parameters <string, string></string,>
     */
    static Map<String,String> queryToMap(String query) {
        Map<String,String> result = new HashMap<>();
        if (query == null) return result;
        for (String param : query.split("&")) {
            String[] pair = param.split("=",2);
            String key = java.net.URLDecoder.decode(pair[0], StandardCharsets.UTF_8);
            String val = pair.length>1 ? java.net.URLDecoder.decode(pair[1], StandardCharsets.UTF_8) : "";
            result.put(key,val);
        }
        return result;
    }

    /**
     * Utility method to convert hexadecimal strings into array of bytes
     * @param hex a hexadecimal string
     * @return the corresponding byte array
     */
    static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Utility method to convert bytes to hexadecimal strings.
     * @param bytes a byte array
     * @return the corresponding hexadecimal string
     */
    static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }


    /**
     * Start the server.
     * @param args ignored
     * @throws Exception any exception
     */
    public static void main(String[] args) throws Exception {
        new Server().startServer();
    }
}
