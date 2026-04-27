package se.iths.jakob.microsoftauthenticator.service;

import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import org.springframework.stereotype.Service;

import java.util.Base64;

@Service
public class MfaService {

    public String generateSecret() {
        SecretGenerator generator = new DefaultSecretGenerator();
        return generator.generate();
    }


    // skapar QR-kod
    public String getQRcode(String secret, String username) {

        QrData data = new QrData.Builder()
                .label(username)
                .secret(secret)
                .issuer("2FA")
                .algorithm(HashingAlgorithm.SHA1)
                .digits(6)
                .period(30)
                .build();

        QrGenerator generator = new ZxingPngQrGenerator();
        try {
            // skapar en bild
            byte[] imageData = generator.generate(data);
            return getDataUriForImage(imageData, generator.getImageMimeType());
        } catch (QrGenerationException e) {
            throw new RuntimeException("Kunde inte skapa QR kod");

        }
    }

    private String getDataUriForImage(byte[] data, String mimeType) {
        String base64 = Base64.getEncoder().encodeToString(data);
        return String.format("data:%s;base64,%s", mimeType, base64);

    }

    
    public boolean verifyCode(String code, String secret) {
        CodeVerifier verifier = new DefaultCodeVerifier(new DefaultCodeGenerator(), new SystemTimeProvider());
        return verifier.isValidCode(secret, code);
    }
}
