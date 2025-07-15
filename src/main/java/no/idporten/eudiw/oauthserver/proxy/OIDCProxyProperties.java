package no.idporten.eudiw.oauthserver.proxy;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import java.net.URI;

@Configuration
@Data
@Slf4j
@Validated
@ConfigurationProperties(prefix = "oidc-proxy")
public class OIDCProxyProperties {

    @Min(1)
    private int connectTimeoutMillis = 5000;
    @Min(1)
    private int readTimeoutMillis = 5000;
    @NotNull
    private URI redirectUri;
    @NotNull
    private OIDCIssuerProperties oidcIssuer;
    @NotNull
    private OIDCClientProperties oidcClient;

}
