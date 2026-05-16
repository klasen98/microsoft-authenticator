package se.iths.jakob.microsoftauthenticator.controller;

import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import se.iths.jakob.microsoftauthenticator.model.AppUser;
import se.iths.jakob.microsoftauthenticator.repository.UserRepository;
import se.iths.jakob.microsoftauthenticator.service.MfaService;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;

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
    public String showMfaCheck(Principal principal, HttpSession session) {

        AppUser user = userRepository.findByUsername(principal.getName());

        // om man inte valt MFA
        if (!user.isMfaEnabled()) {
            session.setAttribute("mfaVerified", true); // ingen MFA = direkt godkänd
            
            return "redirect:/home";
        }

        // om man valt MFA
        return "mfa-login";
    }

    @PostMapping("/login/2fa")
    public String verifyMfa(@RequestParam String code, Principal principal, HttpSession session) {

        AppUser user = userRepository.findByUsername(principal.getName());

        if (mfaService.verifyCode(code, user.getSecretKey())) {
            session.setAttribute("mfaVerified", true); // TOTP godkänd!
            return "redirect:/home";
        }

        return "redirect:/mfa-check?error";
    }

    private static void updateSecurityContext() {
        Authentication currentAuth =
                SecurityContextHolder.getContext().getAuthentication();

        Collection<GrantedAuthority> updateAuth =
                new ArrayList<>(currentAuth.getAuthorities());


        Authentication newAuth =
                new UsernamePasswordAuthenticationToken(
                        currentAuth.getPrincipal(),
                        currentAuth.getCredentials(),
                        updateAuth
                );

        SecurityContextHolder.getContext().setAuthentication(newAuth);
    }
}
