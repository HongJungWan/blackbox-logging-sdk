package io.github.hongjungwan.blackbox.api;

import io.github.hongjungwan.blackbox.core.internal.DefaultSecureLogger;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * SecureLogger 인스턴스 팩토리. 이름별 캐시 관리.
 */
public final class SecureLoggerFactory {

    private static final ConcurrentMap<String, SecureLogger> LOGGER_CACHE = new ConcurrentHashMap<>();

    private SecureLoggerFactory() {}

    /** 이름 기반 로거 획득 또는 생성 */
    public static SecureLogger getLogger(String name) {
        return LOGGER_CACHE.computeIfAbsent(name, DefaultSecureLogger::new);
    }

    /** 클래스 기반 로거 획득 또는 생성 */
    public static SecureLogger getLogger(Class<?> clazz) {
        return getLogger(clazz.getName());
    }

    /** 로거 캐시 초기화 */
    public static void reset() {
        LOGGER_CACHE.clear();
    }
}
