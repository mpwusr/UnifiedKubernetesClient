package org.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.github.cdimascio.dotenv.Dotenv;
import okhttp3.*;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

public class UnifiedKubernetesClient {
    public static void main(String[] args) throws Exception {
        Dotenv dotenv = Dotenv.configure().ignoreIfMissing().load();
        Map<String, Object> cfg = loadJsonConfig(System.getenv("CONFIG_JSON"));

        String api = getValue(cfg, dotenv, "K8S_API", "https://127.0.0.1:6443");
        String namespace = getValue(cfg, dotenv, "NAMESPACE", "default");
        String mode = getValue(cfg, dotenv, "MODE", "").toLowerCase(Locale.ROOT);
        String tokenVal = getValue(cfg, dotenv, "BEARER_TOKEN", null);
        String token = loadToken(tokenVal);
        String caPath = getValue(cfg, dotenv, "CA_CERT_PATH", null);

        String deploymentName = getValue(cfg, dotenv, "DEPLOYMENT_NAME", null);
        String deploymentUri = getValue(cfg, dotenv, "DEPLOYMENT_URI", null);
        String yamlFile = getValue(cfg, dotenv, "YAML_FILE", null);
        String scaleCountStr = getValue(cfg, dotenv, "SCALE_COUNT", "1");

        if (token == null || token.length() < 10) die("No BEARER_TOKEN provided or too short");

        OkHttpClient client = buildClient(caPath);
        System.out.printf("Mode=%s  API=%s  Namespace=%s%n", mode, api, namespace);

        switch (mode) {
            case "apply" -> {
                if (yamlFile == null) die("YAML_FILE must be set for MODE=apply");
                new YamlApplier(client, api, token, namespace).apply(Paths.get(yamlFile));
            }
            case "create", "delete", "scale" -> {
                handleDeploymentAction(client, api, token, namespace, mode, deploymentName, deploymentUri, Integer.parseInt(scaleCountStr));
            }
            default -> die("Invalid MODE. Use apply, create, delete, or scale");
        }
    }

    private static Map<String, Object> loadJsonConfig(String path) {
        if (path == null || path.isBlank()) return null;
        Path p = Paths.get(path);
        if (!Files.exists(p)) return null;
        try {
            return new ObjectMapper().readValue(p.toFile(), Map.class);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to parse CONFIG_JSON", e);
        }
    }

    private static String getValue(Map<String, Object> cfg, Dotenv dotenv, String key, String def) {
        if (cfg != null && cfg.containsKey(key)) return Objects.toString(cfg.get(key));
        String env = dotenv.get(key);
        return env != null ? env : def;
    }

    private static String loadToken(String value) throws IOException {
        if (value == null) return null;
        return value.startsWith("@") ? Files.readString(Path.of(value.substring(1))).trim() : value.trim();
    }

    private static OkHttpClient buildClient(String caPath) throws Exception {
        OkHttpClient.Builder b = new OkHttpClient.Builder();
        if (caPath != null && Files.exists(Path.of(caPath))) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate ca;
            try (InputStream in = Files.newInputStream(Path.of(caPath))) {
                ca = cf.generateCertificate(in);
            }
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            ks.setCertificateEntry("ca", ca);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            X509TrustManager tm = (X509TrustManager) tmf.getTrustManagers()[0];
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, new TrustManager[]{tm}, new SecureRandom());
            b.sslSocketFactory(sc.getSocketFactory(), tm);
        } else {
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, new TrustManager[]{insecureTrustManager()}, new SecureRandom());
            b.sslSocketFactory(sc.getSocketFactory(), insecureTrustManager()).hostnameVerifier((h, s) -> true);
        }
        return b.build();
    }

    private static X509TrustManager insecureTrustManager() {
        return new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        };
    }

    private static void handleDeploymentAction(OkHttpClient client, String api, String token, String ns, String mode, String name, String uri, int scaleCount) throws IOException {
        if (name == null || name.isBlank()) die("DEPLOYMENT_NAME must be set for create/delete/scale");
        if (mode.equals("delete") || mode.equals("scale") || mode.equals("create")) {
            if (mode.equals("delete")) {
                String url = api + "/apis/apps/v1/namespaces/" + ns + "/deployments/" + name;
                Request req = new Request.Builder().url(url).delete().header("Authorization", "Bearer " + token).build();
                try (Response rsp = client.newCall(req).execute()) {
                    printResult("Deleted", rsp);
                }
            } else if (mode.equals("create")) {
                if (uri == null || !(uri.endsWith(".yaml") || uri.endsWith(".yml")))
                    throw new IllegalArgumentException("DEPLOYMENT_URI must end with .yaml or .yml → got: " + uri);
                Map<String, Object> obj = loadYamlToMap(client, uri);
                String kind = Objects.toString(obj.get("kind"), "").toLowerCase();
                String basePath = switch (kind) {
                    case "deployment" -> "/apis/apps/v1/namespaces/" + ns + "/deployments";
                    case "statefulset" -> "/apis/apps/v1/namespaces/" + ns + "/statefulsets";
                    case "coherence" -> "/apis/coherence.oracle.com/v1/namespaces/" + ns + "/coherence";
                    default -> throw new IllegalArgumentException("Unsupported kind in YAML: " + kind);
                };
                String url = api + basePath;
                RequestBody body = RequestBody.create(new ObjectMapper().writeValueAsBytes(obj), MediaType.parse("application/json"));
                Request req = new Request.Builder().url(url).post(body).header("Authorization", "Bearer " + token).header("Content-Type", "application/json").build();
                try (Response rsp = client.newCall(req).execute()) {
                    printResult("Created", rsp);
                }
            } else if (mode.equals("scale")) {
                String url = api + "/apis/apps/v1/namespaces/" + ns + "/deployments/" + name;
                String patch = "{\"spec\":{\"replicas\":" + scaleCount + "}}";
                RequestBody body = RequestBody.create(patch.getBytes(StandardCharsets.UTF_8), MediaType.parse("application/strategic-merge-patch+json"));
                Request req = new Request.Builder().url(url).patch(body).header("Authorization", "Bearer " + token).header("Content-Type", "application/strategic-merge-patch+json").build();
                try (Response rsp = client.newCall(req).execute()) {
                    printResult("Scaled to " + scaleCount, rsp);
                }
            }
        }
    }

    private static void printResult(String action, Response rsp) throws IOException {
        System.out.println(rsp.isSuccessful() ? action + " ✔" : action + " ✖ → " + rsp.code() + "\n" + (rsp.body() != null ? rsp.body().string() : ""));
    }

    private static void die(String msg) {
        System.err.println("✖ " + msg);
        System.exit(1);
    }

    private static Map<String, Object> loadYamlToMap(OkHttpClient client, String uriStr) throws IOException {
        URI uri = URI.create(uriStr);
        ObjectMapper yaml = new ObjectMapper(new YAMLFactory());
        if ("http".equals(uri.getScheme()) || "https".equals(uri.getScheme())) {
            Request fetch = new Request.Builder().url(uriStr).build();
            try (Response r = client.newCall(fetch).execute()) {
                if (!r.isSuccessful() || r.body() == null) throw new IOException("Failed to fetch " + uriStr + " → " + r.code());
                try (InputStream in = r.body().byteStream()) {
                    return yaml.readValue(in, Map.class);
                }
            }
        } else if ("file".equals(uri.getScheme())) {
            try (InputStream in = Files.newInputStream(Path.of(uri))) {
                return yaml.readValue(in, Map.class);
            }
        } else if (Files.exists(Path.of(uriStr))) {
            try (InputStream in = Files.newInputStream(Path.of(uriStr))) {
                return yaml.readValue(in, Map.class);
            }
        }
        throw new IllegalArgumentException("Unsupported DEPLOYMENT_URI: " + uriStr);
    }
}
