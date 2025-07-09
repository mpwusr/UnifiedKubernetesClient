/*
 * UnifiedKubernetesClient.java – one‑stop CLI that merges the capabilities of:
 *   1. KubernetesCombinedJava (create / delete / scale a Deployment from env / JSON / .env)
 *   2. KubernetesSliceYamlJSON  (stream a multi‑doc YAML / CRDs and apply each object)
 *
 * Usage patterns (all values may be set in a .env or CONFIG_JSON file instead of CLI):
 *
 *   MODE=apply  YAML_FILE=manifests.yaml  java UnifiedKubernetesClient
 *   MODE=create DEPLOYMENT_URI=https://example/nginx.yaml  DEPLOYMENT_NAME=nginx java UnifiedKubernetesClient
 *   MODE=delete DEPLOYMENT_NAME=nginx  java UnifiedKubernetesClient
 *   MODE=scale  DEPLOYMENT_NAME=nginx SCALE_COUNT=3  java UnifiedKubernetesClient
 *
 * Required variables:
 *   BEARER_TOKEN   –‑ the service‑account token (string *or* path to file prefixed @)
 *   K8S_API        –‑ https://host:6443 (defaults to https://127.0.0.1:6443)
 *   NAMESPACE      –‑ default namespace for namespaced objects (default "default")
 *
 * Optional:
 *   CA_CERT_PATH   –‑ path to cluster CA certificate; if omitted an *INSECURE* trust‑all
 *                     SSLContext is used (handy for local clusters).
 *
 * The code intentionally avoids extra dependencies beyond OkHttp / Jackson / dotenv.
 */

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.github.cdimascio.dotenv.Dotenv;
import okhttp3.*;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

/* ───────── fetch & parse YAML to Map ───────── */
private static Map<String,Object> loadYamlToMap(
        OkHttpClient client, String uriStr) throws IOException {

    URI uri = URI.create(uriStr);
    ObjectMapper yaml = new ObjectMapper(new YAMLFactory());

    if ("http".equals(uri.getScheme()) || "https".equals(uri.getScheme())) {
        Request fetch = new Request.Builder().url(uriStr).build();
        try (Response r = client.newCall(fetch).execute()) {
            if (!r.isSuccessful() || r.body() == null)
                throw new IOException("Failed to fetch " + uriStr + " → " + r.code());
            try (InputStream in = r.body().byteStream()) {
                return yaml.readValue(in, Map.class);
            }
        }
    }
    if ("file".equals(uri.getScheme())) {
        try (InputStream in = Files.newInputStream(Path.of(uri))) {
            return yaml.readValue(in, Map.class);
        }
    }
    // Fall-back: treat as plain path (relative or absolute)
    if (Files.exists(Path.of(uriStr))) {
        try (InputStream in = Files.newInputStream(Path.of(uriStr))) {
            return yaml.readValue(in, Map.class);
        }
    }
    throw new IllegalArgumentException("Unsupported DEPLOYMENT_URI: " + uriStr);
}


public class UnifiedKubernetesClient {

    /* ───────────────────────────── ENTRY ───────────────────────────── */
    public static void main(String[] args) throws Exception {
        Dotenv dotenv = Dotenv.configure().ignoreIfMissing().load();
        Map<String, Object> cfg = loadJsonConfig(System.getenv("CONFIG_JSON"));

        //────────────────────────── gather config ──────────────────────────//
        String api       = getValue(cfg, dotenv, "K8S_API", "https://127.0.0.1:6443");
        String namespace = getValue(cfg, dotenv, "NAMESPACE", "default");
        String mode      = getValue(cfg, dotenv, "MODE", "").toLowerCase(Locale.ROOT);
        String tokenVal  = getValue(cfg, dotenv, "BEARER_TOKEN", null);
        String token     = loadToken(tokenVal);
        String caPath    = getValue(cfg, dotenv, "CA_CERT_PATH", null);

        String deploymentName = getValue(cfg, dotenv, "DEPLOYMENT_NAME", null);
        String deploymentUri  = getValue(cfg, dotenv, "DEPLOYMENT_URI", null);
        String yamlFile       = getValue(cfg, dotenv, "YAML_FILE", null);
        String scaleCountStr  = getValue(cfg, dotenv, "SCALE_COUNT", "1");

        if (token == null || token.length() < 10) {
            System.err.println("✖ No BEARER_TOKEN provided or too short");
            System.exit(1);
        }

        OkHttpClient client = buildClient(caPath);

        System.out.printf("Mode=%s  API=%s  Namespace=%s%n", mode, api, namespace);

        switch (mode) {
            case "apply" -> {
                if (yamlFile == null) {
                    die("YAML_FILE must be set for MODE=apply");
                }
                new YamlApplier(client, api, token, namespace).apply(Paths.get(yamlFile));
            }
            case "create", "delete", "scale" -> {
                handleDeploymentAction(client, api, token, namespace, mode, deploymentName,
                        deploymentUri, Integer.parseInt(scaleCountStr));
            }
            default -> die("Invalid MODE. Use apply, create, delete, or scale");
        }
    }

    /* ───────────────────────── helpers / util ───────────────────────── */
    private static Map<String,Object> loadJsonConfig(String path) {
        if (path == null || path.isBlank()) return null;
        Path p = Paths.get(path);
        if (!Files.exists(p)) return null;
        try {
            return new ObjectMapper().readValue(p.toFile(), Map.class);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to parse CONFIG_JSON", e);
        }
    }

    private static String getValue(Map<String,Object> cfg, Dotenv dotenv, String key, String def) {
        if (cfg != null && cfg.containsKey(key)) return Objects.toString(cfg.get(key));
        String env = dotenv.get(key);
        return env != null ? env : def;
    }

    private static String loadToken(String value) throws IOException {
        if (value == null) return null;
        if (value.startsWith("@")) {
            return Files.readString(Path.of(value.substring(1))).trim();
        }
        return value.trim();
    }

    private static OkHttpClient buildClient(String caPath) throws Exception {
        OkHttpClient.Builder b = new OkHttpClient.Builder();
        if (caPath != null && Files.exists(Path.of(caPath))) {
            // trust only the supplied CA
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
            // INSECURE: trust‑all
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, new TrustManager[]{insecureTrustManager()}, new SecureRandom());
            b.sslSocketFactory(sc.getSocketFactory(), insecureTrustManager())
                    .hostnameVerifier((h,s) -> true);
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

    private static void handleDeploymentAction(OkHttpClient client,
                                               String api, String token, String ns,
                                               String mode, String name, String uri,
                                               int scaleCount) throws IOException {
        if (name == null || name.isBlank()) {
            die("DEPLOYMENT_NAME must be set for create/delete/scale");
        }
        switch (mode) {
            case "delete" -> {
                String url = api + "/apis/apps/v1/namespaces/" + ns + "/deployments/" + name;
                Request req = new Request.Builder().url(url)
                        .delete()
                        .header("Authorization", "Bearer " + token)
                        .build();
                try (Response rsp = client.newCall(req).execute()) {
                    printResult("Deleted", rsp);
                }
            }
            case "create" -> {
                if (uri == null) die("DEPLOYMENT_URI must be set for create");

                // 🔒 Allow only .yaml or .yml
                if (!(uri.endsWith(".yaml") || uri.endsWith(".yml"))) {
                    throw new IllegalArgumentException("DEPLOYMENT_URI must end with .yaml or .yml → got: " + uri);
                }

                String url = api + "/apis/apps/v1/namespaces/" + ns + "/deployments";

                // Parse YAML → Map
                Map<String, Object> obj = loadYamlToMap(client, uri);

                // Convert to JSON request body
                RequestBody body = RequestBody.create(
                new ObjectMapper().writeValueAsBytes(obj),
                MediaType.parse("application/json"));

                // POST the Deployment
                Request req = new Request.Builder().url(url)
                        .post(body)
                        .header("Authorization", "Bearer " + token)
                        .header("Content-Type", "application/json")
                        .build();

                try (Response rsp = client.newCall(req).execute()) {
                    printResult("Created", rsp);
                }    
            }

            case "scale" -> {
                String url = api + "/apis/apps/v1/namespaces/" + ns + "/deployments/" + name;
                String patch = "{\"spec\":{\"replicas\":" + scaleCount + "}}";
                RequestBody body = RequestBody.create(patch.getBytes(StandardCharsets.UTF_8),
                        MediaType.parse("application/strategic-merge-patch+json"));
                Request req = new Request.Builder().url(url)
                        .patch(body)
                        .header("Authorization", "Bearer " + token)
                        .header("Content-Type", "application/strategic-merge-patch+json")
                        .build();
                try (Response rsp = client.newCall(req).execute()) {
                    printResult("Scaled to " + scaleCount, rsp);
                }
            }
        }
    }

    private static void printResult(String action, Response rsp) throws IOException {
        System.out.println(rsp.isSuccessful()
                ? action + " ✔"
                : action + " ✖ → " + rsp.code() + "\n" + (rsp.body()!=null?rsp.body().string():""));
    }

    private static void die(String msg) {
        System.err.println("✖ " + msg);
        System.exit(1);
    }

    /* ──────────────────────── inner class: YamlApplier ─────────────────────── */
    private static class YamlApplier {
        private static final MediaType JSON = MediaType.parse("application/json");
        private static final ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());
        private static final ObjectMapper jsonMapper = new ObjectMapper();

        private final OkHttpClient client;
        private final String apiServer;
        private final String token;
        private final String defaultNs;

        YamlApplier(OkHttpClient client, String apiServer, String token, String defaultNs) {
            this.client = client;
            this.apiServer = apiServer.replaceAll("/+$", "");
            this.token = token;
            this.defaultNs = defaultNs;
        }

        void apply(Path yamlPath) throws IOException {
            try (InputStream in = Files.newInputStream(yamlPath)) {
                Iterable<Object> docs = new org.yaml.snakeyaml.Yaml().loadAll(in);
                for (Object doc : docs) {
                    if (!(doc instanceof Map<?,?> map) || map.isEmpty()) continue;
                    postObject((Map<String,Object>) map);
                }
            }
        }

        @SuppressWarnings("unchecked")
        private void postObject(Map<String,Object> obj) throws IOException {
            String apiVersion = (String) obj.get("apiVersion");
            String kind       = (String) obj.get("kind");
            if (apiVersion == null || kind == null)
                throw new IllegalArgumentException("YAML object missing apiVersion or kind");

            String group, version;
            String[] gv = apiVersion.split("/", 2);
            if (gv.length == 2) { group = gv[0]; version = gv[1]; }
            else { group=""; version = gv[0]; }

            Map<String,Object> meta = (Map<String,Object>) obj.getOrDefault("metadata", Map.of());
            String ns = (String) meta.getOrDefault("namespace", defaultNs);
            boolean namespaced = ns != null && !ns.isBlank();

            String plural = specialPlural(kind);

            StringBuilder url = new StringBuilder(apiServer);
            if (group.isBlank()) url.append("/api/").append(version);
            else url.append("/apis/").append(group).append('/').append(version);
            if (namespaced) url.append("/namespaces/").append(URLEncoder.encode(ns, StandardCharsets.UTF_8));
            url.append('/').append(plural);

            byte[] bodyBytes = jsonMapper.writeValueAsBytes(obj);
            RequestBody body = RequestBody.create(bodyBytes, JSON);
            Request req = new Request.Builder().url(url.toString())
                    .addHeader("Authorization", "Bearer " + token)
                    .addHeader("Content-Type", "application/json")
                    .post(body)
                    .build();
            try (Response rsp = client.newCall(req).execute()) {
                String name = Objects.toString(meta.get("name"), "<unknown>");
                System.out.printf("%s/%s → %d%n", kind, name, rsp.code());
                if (!rsp.isSuccessful()) {
                    System.out.println(rsp.body()!=null?rsp.body().string():"<no body>");
                }
            }
        }

        private static final Map<String,String> SPECIAL = Map.of(
                "ConfigMap", "configmaps",
                "Secret", "secrets",
                "Ingress", "ingresses",
                "Service", "services",
                "Coherence", "coherence"
        );
        private String specialPlural(String kind) {
            return SPECIAL.getOrDefault(kind, kind.toLowerCase(Locale.ROOT) + "s");
        }
    }
}

