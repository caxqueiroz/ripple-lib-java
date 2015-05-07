package com.ripple.crypto.ecdsa;

import com.ripple.utils.Sha512;
import com.ripple.utils.Utils;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

import static com.ripple.config.Config.getB58IdentiferCodecs;

public class Seed {
    final byte[] seedBytes;
    byte[] version;

    public Seed(byte[] seedBytes) {
        this.seedBytes = seedBytes;
    }

    @Override
    public String toString() {
        return getB58IdentiferCodecs().encodeFamilySeed(seedBytes);
    }

    public byte[] getBytes() {
        return seedBytes;
    }

    public IKeyPair keyPair() {
        return createKeyPair(seedBytes, 0);
    }
    public IKeyPair rootKeyPair() {
        return createKeyPair(seedBytes, -1);
    }

    public IKeyPair keyPair(int account) {
        return createKeyPair(seedBytes, account);
    }

    public static Seed fromBase58(String b58) {
        return new Seed(getB58IdentiferCodecs().decodeFamilySeed(b58));
    }

    public static Seed fromPassPhrase(String passPhrase) {
        return new Seed(passPhraseToSeedBytes(passPhrase));
    }

    public static byte[] passPhraseToSeedBytes(String phrase) {
        try {
            return new Sha512(phrase.getBytes("utf-8")).finish128();
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public static IKeyPair createKeyPair(byte[] seedBytes) {
        return createKeyPair(seedBytes, 0);
    }

    public static IKeyPair createKeyPair(byte[] seedBytes, int accountNumber) {
        BigInteger secret, pub, privateGen;
        // The private generator (aka root private key, master private key)
        privateGen = K256KeyPair.computePrivateGen(seedBytes);
        byte[] publicGenBytes = K256KeyPair.computePublicGenerator(privateGen);

        if (accountNumber == -1) {
            // The root keyPair
            return new K256KeyPair(privateGen, Utils.uBigInt(publicGenBytes));
        }
        else {
            secret = K256KeyPair.computeSecretKey(privateGen, publicGenBytes, accountNumber);
            pub = K256KeyPair.computePublicKey(secret);
            return new K256KeyPair(secret, pub);
        }

    }

    public static IKeyPair getKeyPair(byte[] seedBytes) {
        return createKeyPair(seedBytes, 0);
    }

    public static IKeyPair getKeyPair(String b58) {
        return getKeyPair(getB58IdentiferCodecs().decodeFamilySeed(b58));
    }
}


