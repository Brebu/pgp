package com.brebu.pgp.service;

/**
 * Interfața pentru serviciul de generare de perechi de chei PGP și scrierea acestora în fișiere.
 */
public interface PGPKeyRingCreatorService {

    /**
     * Creează o pereche de chei PGP și le scrie în fișiere într-un format specificat.
     */
    void createKeyRing();
}
