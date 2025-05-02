package com.verint.springsaml.authenticator;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
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

    @GetMapping("success")
    public String success(Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof Saml2Authentication) {
            Saml2Authentication saml2Authentication = (Saml2Authentication) authentication;
            //String username = saml2Authentication.getPrincipal().toString();
            String username = saml2Authentication.getName();
            model.addAttribute("username", username);

        } else if (authentication != null) {
            model.addAttribute("username", authentication.getName());
        } else {
            model.addAttribute("username", "unknown Username");
        }
        return "success";
    }
}
