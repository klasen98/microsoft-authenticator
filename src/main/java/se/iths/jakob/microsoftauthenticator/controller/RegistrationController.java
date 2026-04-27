package se.iths.jakob.microsoftauthenticator.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import se.iths.jakob.microsoftauthenticator.model.AppUser;
import se.iths.jakob.microsoftauthenticator.repository.UserRepository;
import se.iths.jakob.microsoftauthenticator.service.MfaService;

@Controller
public class RegistrationController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private MfaService mfaService;


    @GetMapping("register")
    public String showRegistration(Model model) {
        model.addAttribute("user", new AppUser());
        return "register";

    }

    @PostMapping("/register")
    public String registerUser(@ModelAttribute AppUser user, Model model) {

        // krypterar lösernordet
        user.setPassword(passwordEncoder.encode(user.getPassword()));


        // frågar om MFA
        if (user.isMfaEnabled()) {
            String secret = mfaService.generateSecret();
            user.setSecretKey(secret);
            user.setMfaEnabled(true);


            userRepository.save(user);

            // skapar QR-kod
            String qrCode = mfaService.getQRcode(secret, user.getUsername());

            model.addAttribute("qrCode", qrCode);
            model.addAttribute("secret", secret);
            return "register-success";
        }

        // om man inte vill ha MFA
        userRepository.save(user);
        return "redirect:/login";
    }
}
