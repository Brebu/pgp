package com.brebu.pgp.service;

import lombok.extern.log4j.Log4j2;
import org.apache.camel.CamelContext;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.converter.crypto.PGPDataFormat;
import org.apache.camel.impl.DefaultCamelContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.util.concurrent.CountDownLatch;

/**
 * Serviciu pentru criptarea și decriptarea fișierelor utilizând PGP.
 */
@Service
@Log4j2
public class EncryptDecryptServiceImpl implements EncryptDecryptService {

    // variabile pentru cheile publice și private, parolă și ID utilizator
    @Value("${publicKey}")
    private String publicKey;

    @Value("${privateKey}")
    private String privateKey;

    @Value("${password}")
    private String password;

    @Value("${userId}")
    private String userId;

    // variabile pentru căile folderelor
    @Value("${folderPathGenerated}")
    private String folderPathGenerated;

    @Value("${folderPathEncrypted}")
    private String folderPathEncrypted;

    @Value("${folderPathDecrypted}")
    private String folderPathDecrypted;

    /**
     * Criptează toate fișierele din folderul folderPathGenerated și le salvează în folderPathEncrypted.
     */
    @Override
    public void encryptFilesInFolder() {
        try (CamelContext ctx = new DefaultCamelContext()) {
            // obține toate fișierele din folderul folderPathGenerated
            File[] listOfFiles = new File(folderPathGenerated).listFiles();
            assert listOfFiles != null;
            // declarați CountDownLatch cu dimensiunea listei fișierelor pentru a aștepta până când toate fișierele sunt criptate
            CountDownLatch latch = new CountDownLatch(listOfFiles.length);
            // configurează rutele Apache Camel pentru a cripta fișierele
            ctx.addRoutes(new RouteBuilder() {
                @Override
                public void configure() {
                    PGPDataFormat encryptFormat = new PGPDataFormat();
                    // setează cheia publică și ID-ul utilizatorului pentru criptare
                    encryptFormat.setKeyFileName("file:" + publicKey);
                    encryptFormat.setKeyUserid(userId);
                    encryptFormat.setArmored(true);
                    // citește fișierele din folderPathGenerated, le criptează și le salvează în folderPathEncrypted
                    from("file:" + folderPathGenerated + "?noop=true&delete=false&charset=utf-8")
                            .marshal(encryptFormat)
                            .to("file:" + folderPathEncrypted + "?fileName=${file:name}.gpg")
                            .process(exchange -> latch.countDown());
                }
            });
            // pornește contextul Camel
            ctx.start();
            // așteaptă până când toate fișierele sunt criptate
            latch.await();
            // oprește contextul Camel
            ctx.stop();
        } catch (InterruptedException ie) {
            log.error("InterruptedException: ", ie);
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            log.error("Exception: ", e);
        }
    }

    /**
     * Decriptează toate fișierele din folderPathEncrypted și le salvează în folderPathDecrypted.
     */
    @Override
    public void decryptFilesInFolder() {
        try (CamelContext ctx = new DefaultCamelContext()) {
            // obține toate fișierele din folderul folderPathEncrypted
            File[] listOfFiles = new File(folderPathEncrypted).listFiles();
            assert listOfFiles != null;
            // declarați CountDownLatch cu dimensiunea listei fișierelor pentru a aștepta până când toate fișierele sunt decriptate
            CountDownLatch latch = new CountDownLatch(listOfFiles.length);
            // configurează rutele Apache Camel pentru a decripta fișierele
            ctx.addRoutes(new RouteBuilder() {
                @Override
                public void configure() {
                    PGPDataFormat decryptFormat = new PGPDataFormat();
                    // setează cheia privată, ID-ul utilizatorului și parola pentru decriptare
                    decryptFormat.setKeyFileName("file:" + privateKey);
                    decryptFormat.setKeyUserid(userId);
                    decryptFormat.setPassword(password);
                    decryptFormat.setArmored(true);
                    // citește fișierele din folderPathEncrypted, le decriptează și le salvează în folderPathDecrypted
                    from("file:" + folderPathEncrypted + "?noop=true&delete=false&charset=utf-8")
                            .unmarshal(decryptFormat)
                            .to("file:" + folderPathDecrypted + "?fileName=${file:name.noext}.txt")
                            .process(exchange -> latch.countDown());
                }
            });
            // pornește contextul Camel
            ctx.start();
            // așteaptă până când toate fișierele sunt decriptate
            latch.await();
            // oprește contextul Camel
            ctx.stop();
        } catch (InterruptedException ie) {
            log.error("InterruptedException: ", ie);
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            log.error("Exception: ", e);
        }
    }
}