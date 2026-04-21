package com.jaeckel.ethp2p.android;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;

public final class MainActivity extends Activity {

    private boolean running = false;
    private Button toggleButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        toggleButton = findViewById(R.id.toggleButton);
        TextView statusView = findViewById(R.id.statusView);
        statusView.setText("Tap Start to launch the node.\nWatch logcat for peer activity:\n  adb logcat -s ethp2p.node ethp2p.cache");

        toggleButton.setOnClickListener(v -> {
            Intent svc = new Intent(this, NodeService.class);
            if (running) {
                stopService(svc);
                toggleButton.setText(R.string.start);
            } else {
                ensureNotificationPermission();
                startForegroundService(svc);
                toggleButton.setText(R.string.stop);
            }
            running = !running;
        });
    }

    private void ensureNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                    != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 1);
            }
        }
    }
}
