package no.idporten.eudiw.oauthserver;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class IndexController {

    @GetMapping("/")
    public String index() {
        return "I will be a very nice oauth-server in near future";
    }

}
