package com.brebu.pgp.service;

import lombok.extern.log4j.Log4j2;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import static org.bouncycastle.bcpg.HashAlgorithmTags.SHA256;
import static org.bouncycastle.bcpg.PublicKeyAlgorithmTags.RSA_GENERAL;

/**
 * Serviciul pentru generarea de perechi de chei PGP și scrierea acestora în fișiere.
 * Aceasta utilizeaza biblioteca BouncyCastle pentru generarea cheilor PGP si scrierea lor in fisiere in format ASCII-armored.
 */
@Service
@Log4j2
public class PGPKeyRingCreatorServiceImpl implements PGPKeyRingCreatorService {

    @Value("${publicKey}")
    private String publicKey;

    @Value("${privateKey}")
    private String privateKey;

    @Value("${password}")
    private String password;

    @Value("${userId}")
    private String userId;

    /**
     * Creează o pereche de chei PGP și le scrie în fișierele specificate în proprietățile de configurare.
     */
    @Override
    public void createKeyRing() {

        try {
            // generează o pereche de chei RSA cu lungimea de 2048 biți
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair masterKeyPair = keyPairGenerator.generateKeyPair();

            // transformă perechea de chei într-o pereche de chei PGP
            PGPKeyPair pgpMasterKeyPair = new JcaPGPKeyPair(RSA_GENERAL, masterKeyPair, new Date());

            // construiește un semnatar de conținut utilizând algoritmul SHA-256
            JcaPGPContentSignerBuilder contentSignerBuilder = new JcaPGPContentSignerBuilder(pgpMasterKeyPair.getPublicKey().getAlgorithm(), SHA256);

            // construiește un criptor de cheie secretă utilizând algoritmul AES-256 și parola specificată
            PBESecretKeyEncryptor secretKeyEncryptor = new JcePBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256, SHA256)
                    .setProvider("BC")
                    .build(password.toCharArray());

            PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator();
            subpacketGenerator.setKeyExpirationTime(true, 31536000); // setează perioada de valabilitate la un an

            // generează o pereche de chei PGP și le scrie în fișierele specificate
            PGPKeyRingGenerator keyRingGenerator = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION,
                    pgpMasterKeyPair, userId, null, subpacketGenerator.generate(),
                    null, contentSignerBuilder, secretKeyEncryptor);

            writePublicKeyRing(publicKey, keyRingGenerator);
            writeSecretKeyRing(privateKey, keyRingGenerator);
        } catch (NoSuchAlgorithmException | PGPException | IOException e) {
            log.error(e);
        }


    }

    /**
     * Scrie cheia publică în fișierul specificat utilizând formatul ASCII-armored.
     *
     * @param publicKeyPath    calea către fișierul în care se va scrie cheia publică
     * @param keyRingGenerator generatorul de perechi de chei PGP
     * @throws IOException dacă apare o eroare de citire/scriere în fișier
     */
    private static void writePublicKeyRing(String publicKeyPath, PGPKeyRingGenerator keyRingGenerator) throws IOException {
        try (ArmoredOutputStream publicKeyArmoredOutputStream = new ArmoredOutputStream(new FileOutputStream(publicKeyPath))) {
            keyRingGenerator.generatePublicKeyRing().encode(publicKeyArmoredOutputStream);
        }
    }

    /**
     * Scrie cheia secretă în fișierul specificat utilizând formatul ASCII-armored.
     *
     * @param secretKeyPath    calea către fișierul în care se va scrie cheia secretă
     * @param keyRingGenerator generatorul de perechi de chei PGP
     * @throws IOException dacă apare o eroare de citire/scriere în fișier
     */
    private static void writeSecretKeyRing(String secretKeyPath, PGPKeyRingGenerator keyRingGenerator) throws IOException {
        try (ArmoredOutputStream secretKeyArmoredOutputStream = new ArmoredOutputStream(new FileOutputStream(secretKeyPath))) {
            keyRingGenerator.generateSecretKeyRing().encode(secretKeyArmoredOutputStream);
        }
    }
}