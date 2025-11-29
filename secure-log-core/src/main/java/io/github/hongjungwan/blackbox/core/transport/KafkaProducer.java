package io.github.hongjungwan.blackbox.core.transport;

import io.github.hongjungwan.blackbox.core.config.SecureLogConfig;
import lombok.extern.slf4j.Slf4j;

/**
 * Simplified Kafka producer (placeholder)
 * In production, use actual Kafka client library
 */
@Slf4j
public class KafkaProducer {

    private final SecureLogConfig config;

    public KafkaProducer(SecureLogConfig config) {
        this.config = config;
        log.info("Kafka producer initialized: {}", config.getKafkaBootstrapServers());
    }

    public void send(String topic, byte[] data) {
        // In production, use org.apache.kafka.clients.producer.KafkaProducer
        // For now, just log
        log.debug("Sending {} bytes to Kafka topic: {}", data.length, topic);

        // Simulate send (replace with actual Kafka send)
        // producer.send(new ProducerRecord<>(topic, data));
    }

    public void close() {
        log.info("Kafka producer closed");
    }
}
