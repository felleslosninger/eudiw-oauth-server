package no.idporten.eudiw.oauthserver.cache;

import java.time.Duration;

public interface Cache {
    void put(String key, Object value, Duration duration);

    Object get(String key);

    Object remove(String key);
}
