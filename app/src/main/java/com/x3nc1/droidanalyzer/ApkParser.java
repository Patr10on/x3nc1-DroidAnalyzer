package com.x3nc1.droidanalyzer;

import android.util.Xml;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class ApkParser {

    private static final String[] DANGEROUS_PERMS = {
        "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
        "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS",
        "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "RECEIVE_MMS",
        "READ_CALENDAR", "WRITE_CALENDAR",
        "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
        "CAMERA", "RECORD_AUDIO",
        "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "CALL_PHONE", "USE_SIP",
        "BODY_SENSORS", "ACTIVITY_RECOGNITION",
        "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE",
        "BLUETOOTH_CONNECT", "BLUETOOTH_SCAN", "NEARBY_WIFI_DEVICES",
        "INSTALL_PACKAGES", "REQUEST_INSTALL_PACKAGES",
        "SYSTEM_ALERT_WINDOW", "WRITE_SETTINGS",
        "BIND_ACCESSIBILITY_SERVICE", "BIND_DEVICE_ADMIN",
        "RECEIVE_BOOT_COMPLETED", "FOREGROUND_SERVICE",
        "KILL_BACKGROUND_PROCESSES", "USE_BIOMETRIC", "USE_FINGERPRINT"
    };

    public static String extractManifest(String apkPath, String cacheDir) {
        try {
            File apkFile = new File(apkPath);
            ZipInputStream zis = new ZipInputStream(new FileInputStream(apkFile));
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.getName().equals("AndroidManifest.xml")) {
                    byte[] data = readBytes(zis);
                    zis.close();
                    return decodeAxml(data);
                }
                zis.closeEntry();
            }
            zis.close();
            return "MANIFEST_NOT_FOUND";
        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }

    private static byte[] readBytes(InputStream is) throws Exception {
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int len;
        while ((len = is.read(buf)) != -1) {
            baos.write(buf, 0, len);
        }
        return baos.toByteArray();
    }

    private static String decodeAxml(byte[] data) {
        StringBuilder sb = new StringBuilder();
        try {
            int offset = 0;
            while (offset < data.length - 4) {
                int chunkType = readInt16LE(data, offset);
                int chunkSize = readInt32LE(data, offset + 4);
                if (chunkSize <= 0 || chunkSize > data.length) break;

                if (chunkType == 0x0003) {
                    int stringCount = readInt32LE(data, offset + 4 * 5);
                    int stringsStart = readInt32LE(data, offset + 4 * 7);
                    int[] offsets = new int[stringCount];
                    for (int i = 0; i < stringCount && i < 2048; i++) {
                        offsets[i] = readInt32LE(data, offset + 28 + i * 4);
                    }
                    int base = offset + stringsStart;
                    for (int i = 0; i < stringCount && i < 2048; i++) {
                        int soff = base + offsets[i];
                        if (soff + 2 >= data.length) continue;
                        int len = readInt16LE(data, soff);
                        if (len <= 0 || len > 2048 || soff + 2 + len * 2 > data.length) continue;
                        StringBuilder str = new StringBuilder();
                        for (int c = 0; c < len; c++) {
                            char ch = (char) readInt16LE(data, soff + 2 + c * 2);
                            if (ch > 0) str.append(ch);
                        }
                        if (str.length() > 0) sb.append(str).append("\n");
                    }
                }
                offset += chunkSize;
            }
        } catch (Exception e) {
            sb.append("PARSE_ERROR: ").append(e.getMessage());
        }
        return sb.toString();
    }

    private static int readInt16LE(byte[] data, int offset) {
        if (offset + 1 >= data.length) return 0;
        return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8);
    }

    private static int readInt32LE(byte[] data, int offset) {
        if (offset + 3 >= data.length) return 0;
        return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8)
             | ((data[offset + 2] & 0xFF) << 16) | ((data[offset + 3] & 0xFF) << 24);
    }

    public static String extractDangerousPermissions(String manifestContent) {
        if (manifestContent == null || manifestContent.isEmpty()) return "No permissions found.";
        List<String> found = new ArrayList<>();
        String upper = manifestContent.toUpperCase();
        for (String perm : DANGEROUS_PERMS) {
            if (upper.contains(perm)) {
                found.add("android.permission." + perm);
            }
        }
        if (found.isEmpty()) return "No dangerous permissions detected.";
        StringBuilder sb = new StringBuilder();
        for (String p : found) sb.append(p).append("\n");
        return sb.toString().trim();
    }

    public static String scanForIPs(String apkPath, String cacheDir) {
        Pattern ipPattern = Pattern.compile(
            "(?<![\\d.])(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)(?![\\d.])"
        );
        Set<String> results = new HashSet<>();
        scanZipContents(apkPath, ipPattern, results, new String[]{".smali", ".json", ".xml", ".txt", ".js", ".html", ".properties", ".dex"});
        if (results.isEmpty()) return "No IP addresses found.";
        return String.join("\n", results);
    }

    public static String scanForApiKeys(String apkPath, String cacheDir) {
        Pattern apiPattern = Pattern.compile(
            "(?:api[_\\-]?key|apikey|secret[_\\-]?key|access[_\\-]?token|auth[_\\-]?token|bearer|private[_\\-]?key)" +
            "\\s*[=:\"'\\s]+\\s*([A-Za-z0-9\\-_]{16,80})",
            Pattern.CASE_INSENSITIVE
        );
        Set<String> results = new HashSet<>();
        scanZipContents(apkPath, apiPattern, results, new String[]{".json", ".xml", ".txt", ".js", ".html", ".properties", ".smali"});
        if (results.isEmpty()) return "No API keys found.";
        return String.join("\n", results);
    }

    public static String scanForUrls(String apkPath, String cacheDir) {
        Pattern urlPattern = Pattern.compile(
            "https?://[A-Za-z0-9\\-._~:/?#\\[\\]@!$&'()*+,;=%]{4,200}"
        );
        Set<String> results = new HashSet<>();
        scanZipContents(apkPath, urlPattern, results, new String[]{".smali", ".json", ".xml", ".txt", ".js", ".html", ".properties"});
        if (results.isEmpty()) return "No URLs found.";
        return String.join("\n", results);
    }

    private static void scanZipContents(String apkPath, Pattern pattern, Set<String> results, String[] extensions) {
        try {
            ZipInputStream zis = new ZipInputStream(new FileInputStream(apkPath));
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName().toLowerCase();
                boolean matches = false;
                for (String ext : extensions) {
                    if (name.endsWith(ext)) { matches = true; break; }
                }
                if (matches && !entry.isDirectory()) {
                    byte[] data = readBytes(zis);
                    String text = new String(data, StandardCharsets.UTF_8);
                    Matcher m = pattern.matcher(text);
                    int count = 0;
                    while (m.find() && count < 50) {
                        String val = m.groupCount() > 0 ? m.group(1) : m.group();
                        if (val != null && val.length() > 3) {
                            results.add(val.trim());
                            count++;
                        }
                    }
                }
                zis.closeEntry();
                if (results.size() > 200) break;
            }
            zis.close();
        } catch (Exception ignored) {}
    }
}