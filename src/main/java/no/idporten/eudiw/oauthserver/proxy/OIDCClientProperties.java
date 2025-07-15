package no.idporten.eudiw.oauthserver.proxy;

import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;

public record OIDCClientProperties(ClientID clientID, Secret clientSecret) {

}
