package com.keith.adhesive;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.zip.Adler32;

public class Adhesive {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        File sourceApk = new File("files/source.apk");
        File dexParser = new File("files/parser.dex");

        byte[] sourceApkEncryptedArray = encrypt(readFileBytes(sourceApk));
        byte[] dexParserArray = readFileBytes(dexParser);

        int sourceApkLength = sourceApkEncryptedArray.length;
        int dexParserLength = dexParserArray.length;

        int totalLength = sourceApkLength + dexParserLength + 4;
        byte[] resultDex = new byte[totalLength];

        System.arraycopy(dexParserArray, 0, resultDex, 0, dexParserLength);
        System.arraycopy(sourceApkEncryptedArray, 0, resultDex, dexParserLength, sourceApkLength);
        System.arraycopy(intToByte(sourceApkLength), 0, resultDex, totalLength - 4, 4);

        adjustFileSizeHeader(resultDex);
        adjustSHA1Header(resultDex);
        fixCheckSumHeader(resultDex);

        byteArrayToFile(resultDex, "files/classes.dex");
    }

    private static byte[] encrypt(byte[] data) {
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (0xFF ^ data[i]);
        }
        return data;
    }

    private static byte[] readFileBytes(File file) throws IOException {
        FileInputStream fis = new FileInputStream(file);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        while (true) {
            int length = fis.read(buffer);
            if (length != -1) {
                baos.write(buffer, 0, length);
            } else {
                return baos.toByteArray();
            }
        }
    }

    private static byte[] intToByte(int value) {
        byte[] result = new byte[4];
        for (int i = 3; i >= 0; i--) {
            result[i] = (byte) (value % 256);
            value >>= 8;
        }
        return result;
    }

    private static void adjustFileSizeHeader(byte[] dexArray) {
        byte[] dexFZ = intToByte(dexArray.length);
        byte[] reverseFZ = new byte[4];
        for (int i = 0; i < reverseFZ.length; i++) {
            reverseFZ[i] = dexFZ[reverseFZ.length - 1 - i];
        }
        System.arraycopy(reverseFZ, 0, dexArray, 32, reverseFZ.length);
    }

    private static void adjustSHA1Header(byte[] dexArray) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(dexArray, 32, dexArray.length - 32);
        byte[] resultDT = md.digest();
        System.arraycopy(resultDT, 0, dexArray, 12, 20);
    }

    private static void fixCheckSumHeader(byte[] dexArray) {
        Adler32 adler = new Adler32();
        adler.update(dexArray, 12, dexArray.length - 12);
        long value = adler.getValue();
        byte[] resultCS = intToByte((int) value);
        byte[] reverseCS = new byte[4];
        for (int i = 0; i < reverseCS.length; i++) {
            reverseCS[i] = resultCS[reverseCS.length - 1 - i];
        }
        System.arraycopy(reverseCS, 0, dexArray, 8, reverseCS.length);
    }

    private static void byteArrayToFile(byte[] data, String fileName) throws IOException {
        File file = new File(fileName);
        boolean isFileExist = file.exists();
        if (!isFileExist) {
            isFileExist = file.createNewFile();
        }
        if (isFileExist) {
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(data);
            fos.flush();
            fos.close();
        }
    }

}
