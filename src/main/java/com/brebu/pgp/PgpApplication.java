package com.brebu.pgp;

import com.brebu.pgp.service.EncryptDecryptService;
import com.brebu.pgp.service.PGPKeyRingCreatorServiceImpl;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.Security;

/**
 * Clasa principală a aplicației PGP, care pornește aplicația și execută serviciile criptografice
 */
@SpringBootApplication
@RequiredArgsConstructor
public class PgpApplication implements CommandLineRunner {

    /**
     * Serviciul utilizat pentru crearea unui set de chei PGP
     */
    @NonNull
    private final PGPKeyRingCreatorServiceImpl pgpKeyRingCreatorService;

    /**
     * Serviciul utilizat pentru criptarea și decriptarea fișierelor
     */
    @NonNull
    private final EncryptDecryptService encryptDecryptService;

    /**
     * Metoda principală care pornește aplicația și execută serviciile criptografice
     *
     * @param args Argumentele liniei de comandă, care nu sunt utilizate în acest caz
     */
    public static void main(String[] args) {
        SpringApplication.run(PgpApplication.class, args);
    }

    /**
     * Metoda care rulează automat la pornirea aplicației și execută serviciile criptografice
     *
     * @param args Argumentele liniei de comandă, care nu sunt utilizate în acest caz
     */
    @Override
    public void run(String... args) {
        // Adaugă providerul Bouncy Castle pentru criptare și decriptare
        Security.addProvider(new BouncyCastleProvider());

        // Crează un set de chei PGP
        pgpKeyRingCreatorService.createKeyRing();

        // Criptează toate fișierele dintr-un director
        encryptDecryptService.encryptFilesInFolder();

        // Decriptează toate fișierele dintr-un director
        encryptDecryptService.decryptFilesInFolder();
    }
}