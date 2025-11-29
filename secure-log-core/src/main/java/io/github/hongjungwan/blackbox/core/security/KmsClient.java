package io.github.hongjungwan.blackbox.core.security;

import io.github.hongjungwan.blackbox.core.config.SecureLogConfig;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.locks.ReentrantLock;

/**
 * KMS (Key Management Service) Client
 * Retrieves KEK (Key Encryption Key) from external KMS
 *
 * CRITICAL: Uses ReentrantLock instead of synchronized (Virtual Thread compatible)
 */
@Slf4j
public class KmsClient {

    private final SecureLogConfig config;
    private final HttpClient httpClient;
    private final ReentrantLock lock = new ReentrantLock();

    // Cached KEK (with TTL)
    private volatile SecretKey cachedKek;
    private volatile long kekCacheTime;
    private static final long KEK_CACHE_TTL_MS = 300_000; // 5 minutes

    public KmsClient(SecureLogConfig config) {
        this.config = config;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(config.getKmsTimeoutMs()))
                .build();
    }

    /**
     * Get KEK from KMS (with caching)
     * Uses ReentrantLock instead of synchronized for Virtual Thread compatibility
     */
    public SecretKey getKek() {
        // Check cache first
        if (isCacheValid()) {
            return cachedKek;
        }

        // Acquire lock (Virtual Thread compatible)
        lock.lock();
        try {
            // Double-check after acquiring lock
            if (isCacheValid()) {
                return cachedKek;
            }

            // Fetch from KMS
            SecretKey kek = fetchKekFromKms();
            cachedKek = kek;
            kekCacheTime = System.currentTimeMillis();

            return kek;

        } catch (Exception e) {
            log.error("Failed to fetch KEK from KMS", e);

            // Fallback: use embedded key (NOT recommended for production)
            log.warn("Using fallback embedded KEK - THIS IS NOT SECURE FOR PRODUCTION");
            return generateFallbackKek();

        } finally {
            lock.unlock();
        }
    }

    private boolean isCacheValid() {
        return cachedKek != null &&
                (System.currentTimeMillis() - kekCacheTime) < KEK_CACHE_TTL_MS;
    }

    /**
     * Fetch KEK from external KMS
     */
    private SecretKey fetchKekFromKms() throws IOException, InterruptedException {
        if (config.getKmsEndpoint() == null) {
            throw new IllegalStateException("KMS endpoint not configured");
        }

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(config.getKmsEndpoint() + "/keys/master"))
                .timeout(Duration.ofMillis(config.getKmsTimeoutMs()))
                .GET()
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new IOException("KMS returned status: " + response.statusCode());
        }

        // Parse response and reconstruct key
        // In production, this would decode the actual key material
        return parseKekFromResponse(response.body());
    }

    private SecretKey parseKekFromResponse(String body) {
        // Simplified: In production, decode actual key from KMS response
        // For now, generate a key (this is just a placeholder)
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            return keyGen.generateKey();
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse KEK", e);
        }
    }

    /**
     * Generate fallback KEK for development/testing
     * WARNING: NOT secure for production use
     */
    private SecretKey generateFallbackKek() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            return keyGen.generateKey();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate fallback KEK", e);
        }
    }

    /**
     * Rotate KEK (trigger key rotation in KMS)
     */
    public void rotateKek() {
        lock.lock();
        try {
            // Invalidate cache
            cachedKek = null;
            kekCacheTime = 0;

            // Trigger rotation in KMS (if supported)
            if (config.getKmsEndpoint() != null) {
                triggerKmsRotation();
            }

            log.info("KEK rotation triggered");

        } finally {
            lock.unlock();
        }
    }

    private void triggerKmsRotation() {
        // Call KMS rotation API
        // Implementation depends on KMS provider
        log.info("Triggering KMS rotation for KEK");
    }
}
