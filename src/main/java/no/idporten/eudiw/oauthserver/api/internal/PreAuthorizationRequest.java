package no.idporten.eudiw.oauthserver.api.internal;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class PreAuthorizationRequest {

    @JsonProperty("sub")
    private String sub;
    @JsonProperty("scope")
    private List<String> scope;
    @JsonProperty("tx_code_challenge")
    private String txCodeChallenge;
    @JsonProperty("tx_id")
    private String txId;
    @JsonProperty("authorization_token_lifetime")
    private int authorizationLifetimeSeconds = 120;

}
