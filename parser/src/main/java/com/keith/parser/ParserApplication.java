package com.keith.parser;

import android.app.Application;
import android.app.Instrumentation;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.os.Bundle;
import android.util.ArrayMap;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import dalvik.system.DexClassLoader;

/**
 * Author: Keith
 * Date: 2017/7/26
 */

@SuppressWarnings("unchecked")
public class ParserApplication extends Application {
    private static final String APPKEY = "APPLICATION_CLASS_NAME";
    private String apkFileName;
    private String odexPath;
    private String libPath;

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        try {
            File odex = getDir("payload_odex", MODE_PRIVATE);
            File libs = getDir("payload_lib", MODE_PRIVATE);
            odexPath = odex.getAbsolutePath();
            libPath = libs.getAbsolutePath();
            apkFileName = odex.getAbsolutePath() + "/payload.apk";
            File dexFile = new File(apkFileName);
            boolean isDexFileExists = dexFile.exists();
            if (!isDexFileExists) {
                isDexFileExists = dexFile.createNewFile();
                byte[] dexData = readDexFileFromApk();
                splitPayLoadFromDex(dexData);
            }
            Object currentActivityThread = Reflector.invokeStaticMethod(
                    "android.app.ActivityThread",
                    "currentActivityThread",
                    new Class[]{},
                    new Object[]{}
            );
            String packageName = getPackageName();
            ArrayMap mPackages = (ArrayMap) Reflector.getFieldOjbect(
                    "android.app.ActivityThread",
                    currentActivityThread,
                    "mPackages"
            );
            WeakReference mPackageRef = (WeakReference) mPackages.get(packageName);
            DexClassLoader dexClassLoader = new DexClassLoader(
                    apkFileName, odexPath, libPath,
                    (ClassLoader) Reflector.getFieldOjbect(
                            "android.app.LoadedApk",
                            mPackageRef.get(),
                            "mClassLoader")
            );
            Reflector.setFieldOjbect("android.app.LoadedApk",
                    "mClassLoader", mPackageRef.get(), dexClassLoader);
            dexClassLoader.loadClass("com.keith.source.SourceActivity");
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        String appClassName = null;
        try {
            ApplicationInfo appInfo = getPackageManager().getApplicationInfo(
                    getPackageName(), PackageManager.GET_META_DATA);
            Bundle bundle = appInfo.metaData;
            if (bundle != null && bundle.containsKey("APPLICATION_CLASS_NAME")) {
                appClassName = bundle.getString("APPLICATION_CLASS_NAME");
            } else {
                return;
            }
            Object currentActivityThread = Reflector.invokeStaticMethod(
                    "android.app.ActivityThread",
                    "currentActivityThread",
                    new Class[]{},
                    new Object[]{}
            );
            Object mBoundApplication = Reflector.getFieldOjbect(
                    "android.app.ActivityThread",
                    currentActivityThread,
                    "mBoundApplication"
            );
            Object loadedApkInfo = Reflector.getFieldOjbect(
                    "android.app.ActivityThread$AppBindData",
                    mBoundApplication, "info"
            );
            Reflector.setFieldOjbect("android.app.LoadedApk",
                    "mApplication", loadedApkInfo, null);
            Object oldApplication = Reflector.getFieldOjbect(
                    "android.app.ActivityThread",
                    currentActivityThread, "mInitialApplication"
            );
            ArrayList<Application> mAllApplications = (ArrayList<Application>) Reflector.getFieldOjbect(
                    "android.app.ActivityThread",
                    currentActivityThread,
                    "mAllApplications"
            );
            mAllApplications.remove(oldApplication);

            ApplicationInfo appInfoInLoadedApk = (ApplicationInfo) Reflector.getFieldOjbect(
                    "android.app.LoadedApk", loadedApkInfo,
                    "mApplicationInfo"
            );
            ApplicationInfo appInfoInAppBindData = (ApplicationInfo) Reflector.getFieldOjbect(
                    "android.app.ActivityThread$AppBindData",
                    mBoundApplication, "appInfo"
            );
            appInfoInLoadedApk.className = appClassName;
            appInfoInAppBindData.className = appClassName;
            Application app = (Application) Reflector.invokeMethod("android.app.LaodedApk",
                    "makeApplication", loadedApkInfo, new Class[]{boolean.class, Instrumentation.class},
                    new Object[]{false, null});
            Reflector.setFieldOjbect("android.app.ActivityThread",
                    "mInitialApplication", currentActivityThread, app);

            ArrayMap mProviderMap = (ArrayMap) Reflector.getFieldOjbect(
                    "android.app.ActivityThread", currentActivityThread,
                    "mProviderMap"
            );
            for (Object providerClientRecord : mProviderMap.values()) {
                Object localProvider = Reflector.getFieldOjbect(
                        "android.app.ActivityThread$ProviderClientRecord",
                        providerClientRecord, "mLocalProvider"
                );
                Reflector.setFieldOjbect(
                        "android.content.ContentProvider",
                        "mContext", localProvider, app);
            }
        } catch (NameNotFoundException e) {
            e.printStackTrace();
        }
    }

    private byte[] readDexFileFromApk() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        FileInputStream fis = new FileInputStream(getApplicationInfo().sourceDir);
        BufferedInputStream bis = new BufferedInputStream(fis);
        ZipInputStream zis = new ZipInputStream(bis);
        while (true) {
            ZipEntry entry = zis.getNextEntry();
            if (entry == null) {
                zis.close();
                break;
            }
            if (entry.getName().equals("classes.dex")) {
                byte[] buffer = new byte[1024];
                while (true) {
                    int length = zis.read(buffer);
                    if (length == -1) {
                        break;
                    }
                    baos.write(buffer, 0, length);
                }
            }
            zis.closeEntry();
        }
        zis.close();
        return baos.toByteArray();
    }

    private void splitPayLoadFromDex(byte[] apkArray) throws IOException {
        int apkLength = apkArray.length;
        byte[] dexLengthArray = new byte[4];
        System.arraycopy(apkArray, apkLength - 4, dexLengthArray, 0, 4);
        ByteArrayInputStream bais = new ByteArrayInputStream(dexLengthArray);
        DataInputStream dis = new DataInputStream(bais);
        int sourceApkLength = dis.readInt();
        byte[] sourceApkArray = new byte[sourceApkLength];
        System.arraycopy(apkArray, apkLength - 4 - sourceApkLength, sourceApkArray, 0, sourceApkLength);

        sourceApkArray = decrypt(sourceApkArray);

        File apk = new File(apkFileName);
        FileOutputStream fos = new FileOutputStream(apk);
        fos.write(sourceApkArray);
        fos.close();

        FileInputStream fis = new FileInputStream(apk);
        BufferedInputStream bis = new BufferedInputStream(fis);
        ZipInputStream zis = new ZipInputStream(bis);
        while (true) {
            ZipEntry entry = zis.getNextEntry();
            if (entry == null) {
                zis.close();
                break;
            }
            String name = entry.getName();
            if (name.startsWith("lib/") && name.endsWith(".so")) {
                File storeFile = new File(libPath + "/" + name.substring(name.lastIndexOf('/')));
                if (storeFile.createNewFile()) {
                    FileOutputStream storeOS = new FileOutputStream(storeFile);
                    byte[] buffer = new byte[1024];
                    while (true) {
                        int length = zis.read(buffer);
                        if (length == -1) {
                            break;
                        }
                        storeOS.write(buffer, 0, length);
                    }
                    storeOS.flush();
                    storeOS.close();
                }
            }
            zis.closeEntry();
        }
    }

    private byte[] decrypt(byte[] data) {
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (0xFF ^ data[i]);
        }
        return data;
    }
}
