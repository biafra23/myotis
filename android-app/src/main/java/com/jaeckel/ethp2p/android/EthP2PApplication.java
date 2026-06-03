package com.jaeckel.ethp2p.android;

import android.app.Application;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public final class EthP2PApplication extends Application {

    @Override
    public void onCreate() {
        super.onCreate();
        // Android ships a stripped-down "BC" provider that lacks ECDSA.
        // Replace it with the full BouncyCastle we bundle so Tuweni's
        // SECP256K1 / Hash.keccak256 / etc. resolve.
        //
        // Critically, append (addProvider) rather than insertProviderAt(1).
        // Default Android provider order has AndroidOpenSSL (BoringSSL-backed)
        // at position 1 — which is what we want for unqualified
        // Cipher.getInstance("AES/CTR/NoPadding") and "AES/GCM/NoPadding"
        // calls inside the discv5 library. Boosting BC to position 1 puts BC
        // on the AES path, where its CTR/GCM implementation does not
        // round-trip correctly with discv5 peers in practice (an empirical
        // finding from the Portal Client Samba port). Keeping AndroidOpenSSL
        // at the top and BC at the bottom: AES routes via AndroidOpenSSL,
        // SECP256K1 falls through to BC because no upper provider supplies
        // it on Android.
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.addProvider(new BouncyCastleProvider());
    }
}
