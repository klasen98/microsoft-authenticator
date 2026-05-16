package se.iths.jakob.microsoftauthenticator.controller;

import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import se.iths.jakob.microsoftauthenticator.model.AppUser;
import se.iths.jakob.microsoftauthenticator.repository.UserRepository;

import java.security.Principal;

@Controller
public class HomeController {


    @Autowired
    private UserRepository userRepository;

    @GetMapping("/home")
    public String showHome(Principal principal, Model model, HttpSession session) {

        if (principal == null) {
            return "redirect:/login";

        }
        if (!Boolean.TRUE.equals(session.getAttribute("mfaVerified"))) {
            return "redirect:/mfa-check";
        }

        String username = principal.getName();
        AppUser user = userRepository.findByUsername(username);

        model.addAttribute("username", username);
        model.addAttribute("mfaActive", user.isMfaEnabled());

        return "home";
    }

}