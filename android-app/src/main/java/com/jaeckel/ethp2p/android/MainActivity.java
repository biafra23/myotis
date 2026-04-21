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
            if (NodeService.isRunning()) {
                stopService(svc);
            } else {
                ensureNotificationPermission();
                startForegroundService(svc);
            }
            // Let onResume reconcile the label once the service state has flipped.
            refreshButtonLabel();
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        // Activity is recreated on configuration changes (rotation, theme); the
        // service process survives, so read truth from its static flag.
        refreshButtonLabel();
    }

    private void refreshButtonLabel() {
        toggleButton.setText(NodeService.isRunning() ? R.string.stop : R.string.start);
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
