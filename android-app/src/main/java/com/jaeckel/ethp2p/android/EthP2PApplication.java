package com.jaeckel.ethp2p.android;

import android.app.Application;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public final class EthP2PApplication extends Application {

    @Override
    public void onCreate() {
        super.onCreate();
        // BouncyCastle ships its own SECP256K1 implementation; the platform provider
        // on Android may be missing curves we need.
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }
}
