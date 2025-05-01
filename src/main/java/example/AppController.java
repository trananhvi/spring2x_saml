package example;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpSession;

@Controller
public class AppController {

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping("/login")
    public String loginPage() {
        return "login"; // This will return login.html from templates folder
    }

    @PostMapping("/process-email")
    public RedirectView processEmail(@RequestParam("email") String email, HttpSession session) {
        // Store the email in the session
        session.setAttribute("login_hint_email", email);
        // Redirect to the SAML SP initiation URL
        return new RedirectView("/sample-sp/saml2/authenticate/v2");
    }
}
