package com.x3nc1.droidanalyzer;

import android.content.ContentResolver;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.ProgressBar;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class AnalyzeActivity extends AppCompatActivity {

    private TextView tvStatus;
    private ProgressBar progressBar;
    private ExecutorService executor;
    private Handler mainHandler;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_analyze);

        tvStatus = findViewById(R.id.tv_status);
        progressBar = findViewById(R.id.progress_bar);
        executor = Executors.newSingleThreadExecutor();
        mainHandler = new Handler(Looper.getMainLooper());

        Uri apkUri = getIntent().getData();
        if (apkUri != null) {
            startAnalysis(apkUri);
        } else {
            finish();
        }
    }

    private void startAnalysis(Uri apkUri) {
        executor.execute(() -> {
            try {
                updateStatus("> Initializing scanner...");
                Thread.sleep(400);

                updateStatus("> Copying APK to cache...");
                File cachedApk = copyUriToCache(apkUri);
                Thread.sleep(400);

                updateStatus("> Extracting AndroidManifest.xml...");
                String manifestContent = ApkParser.extractManifest(cachedApk.getAbsolutePath(), getCacheDir().getAbsolutePath());
                Thread.sleep(400);

                updateStatus("> Scanning for dangerous permissions...");
                String permissions = ApkParser.extractDangerousPermissions(manifestContent);
                Thread.sleep(400);

                updateStatus("> Scanning for IP addresses...");
                String ips = ApkParser.scanForIPs(cachedApk.getAbsolutePath(), getCacheDir().getAbsolutePath());
                Thread.sleep(400);

                updateStatus("> Scanning for API keys...");
                String apiKeys = ApkParser.scanForApiKeys(cachedApk.getAbsolutePath(), getCacheDir().getAbsolutePath());
                Thread.sleep(400);

                updateStatus("> Scanning for URLs...");
                String urls = ApkParser.scanForUrls(cachedApk.getAbsolutePath(), getCacheDir().getAbsolutePath());
                Thread.sleep(400);

                updateStatus("> Analysis complete. Loading results...");
                Thread.sleep(300);

                Intent intent = new Intent(this, ResultActivity.class);
                intent.putExtra("apk_name", cachedApk.getName());
                intent.putExtra("permissions", permissions);
                intent.putExtra("ips", ips);
                intent.putExtra("api_keys", apiKeys);
                intent.putExtra("urls", urls);

                mainHandler.post(() -> {
                    startActivity(intent);
                    finish();
                });

            } catch (Exception e) {
                mainHandler.post(() -> tvStatus.setText("> ERROR: " + e.getMessage()));
            }
        });
    }

    private void updateStatus(String msg) {
        mainHandler.post(() -> tvStatus.setText(msg));
    }

    private File copyUriToCache(Uri uri) throws Exception {
        ContentResolver cr = getContentResolver();
        File outFile = new File(getCacheDir(), "target.apk");
        try (InputStream in = cr.openInputStream(uri);
             FileOutputStream out = new FileOutputStream(outFile)) {
            byte[] buf = new byte[8192];
            int len;
            while ((len = in.read(buf)) != -1) {
                out.write(buf, 0, len);
            }
        }
        return outFile;
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (executor != null) executor.shutdown();
    }
}