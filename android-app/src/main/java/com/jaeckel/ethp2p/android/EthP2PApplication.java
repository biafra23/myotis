package com.jaeckel.ethp2p.android;

import android.app.Application;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public final class EthP2PApplication extends Application {

    @Override
    public void onCreate() {
        super.onCreate();
        // Android ships a stripped-down provider also named "BC" that lacks ECDSA.
        // Replace it with the full BouncyCastle we bundle so Tuweni's SECP256K1 works.
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }
}
