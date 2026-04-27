package se.iths.jakob.microsoftauthenticator.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import se.iths.jakob.microsoftauthenticator.model.AppUser;
import se.iths.jakob.microsoftauthenticator.repository.UserRepository;
import se.iths.jakob.microsoftauthenticator.service.MfaService;

import java.security.Principal;

@Controller
public class LoginController {

    @Autowired
    private MfaService mfaService;

    @Autowired
    private UserRepository userRepository;


    @GetMapping("/login")
    public String showLoginPage() {
        return "login";
    }

    @GetMapping("/mfa-check")
    public String showMfaCheck(Principal principal) {

        AppUser user = userRepository.findByUsername(principal.getName());

        // om man inte valt MFA
        if (!user.isMfaEnabled()) {
            return "redirect:/home";
        }

        // om man valt MFA
        return "mfa-login";
    }

    @PostMapping("/login/2fa")
    public String verifyMfa(@RequestParam String code, Principal principal) {

        AppUser user = userRepository.findByUsername(principal.getName());

        if (mfaService.verifyCode(code, user.getSecretKey())) {
            return "redirect:/home";
        }

        return "redirect:/mfa-check?error";
    }
}
