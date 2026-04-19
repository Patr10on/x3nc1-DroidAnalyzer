package com.x3nc1.droidanalyzer;

import android.os.Bundle;
import android.widget.TextView;
import android.widget.ScrollView;
import androidx.appcompat.app.AppCompatActivity;

public class ResultActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_result);

        String apkName = getIntent().getStringExtra("apk_name");
        String permissions = getIntent().getStringExtra("permissions");
        String ips = getIntent().getStringExtra("ips");
        String apiKeys = getIntent().getStringExtra("api_keys");
        String urls = getIntent().getStringExtra("urls");

        TextView tvApkName = findViewById(R.id.tv_apk_name);
        TextView tvPermissions = findViewById(R.id.tv_permissions);
        TextView tvIps = findViewById(R.id.tv_ips);
        TextView tvApiKeys = findViewById(R.id.tv_api_keys);
        TextView tvUrls = findViewById(R.id.tv_urls);

        tvApkName.setText("> TARGET: " + apkName);
        tvPermissions.setText(permissions != null ? permissions : "N/A");
        tvIps.setText(ips != null ? ips : "N/A");
        tvApiKeys.setText(apiKeys != null ? apiKeys : "N/A");
        tvUrls.setText(urls != null ? urls : "N/A");
    }
}