package com.brebu.pgp.service;

/**
 * Interfața pentru serviciul de criptare și decriptare a fișierelor utilizând PGP.
 */
public interface EncryptDecryptService {

    /**
     * Criptează toate fișierele din folderul specificat și le salvează într-un alt folder.
     */
    void encryptFilesInFolder();

    /**
     * Decriptează toate fișierele din folderul specificat și le salvează într-un alt folder.
     */
    void decryptFilesInFolder();
}