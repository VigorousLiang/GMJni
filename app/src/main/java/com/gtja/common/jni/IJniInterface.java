package com.gtja.common.jni;

import android.content.Context;

public class IJniInterface {

    static {
        System.loadLibrary("GtjaGM");
    }

    public final static byte[] sm2PrivateKey = new byte[]{
            (byte) 0x30, (byte) 0x77, (byte) 0x02, (byte) 0x01, (byte) 0x01, (byte) 0x04, (byte) 0x20, (byte) 0x28,
            (byte) 0x7d, (byte) 0x3f, (byte) 0xb9, (byte) 0xf4, (byte) 0xbb, (byte) 0xc8, (byte) 0xbd, (byte) 0xe1,
            (byte) 0x54, (byte) 0x75, (byte) 0x87, (byte) 0x9f, (byte) 0x08, (byte) 0x61, (byte) 0x20, (byte) 0xe3,
            (byte) 0x65, (byte) 0xf8, (byte) 0xb2, (byte) 0xca, (byte) 0x14, (byte) 0x26, (byte) 0x81, (byte) 0xf6,
            (byte) 0x1e, (byte) 0xd8, (byte) 0x7f, (byte) 0xc0, (byte) 0x66, (byte) 0x20, (byte) 0x29, (byte) 0xa0,
            (byte) 0x0a, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x81, (byte) 0x1c, (byte) 0xcf, (byte) 0x55,
            (byte) 0x01, (byte) 0x82, (byte) 0x2d, (byte) 0xa1, (byte) 0x44, (byte) 0x03, (byte) 0x42, (byte) 0x00,
            (byte) 0x04, (byte) 0xb1, (byte) 0x1e, (byte) 0x4c, (byte) 0x8c, (byte) 0xa9, (byte) 0x02, (byte) 0xf2,
            (byte) 0x8d, (byte) 0x8b, (byte) 0x98, (byte) 0xd2, (byte) 0xd0, (byte) 0xc4, (byte) 0xf1, (byte) 0x60,
            (byte) 0x91, (byte) 0xfb, (byte) 0x61, (byte) 0x62, (byte) 0x00, (byte) 0xcf, (byte) 0x93, (byte) 0x4e,
            (byte) 0x3f, (byte) 0xca, (byte) 0xfd, (byte) 0xf7, (byte) 0x9d, (byte) 0x76, (byte) 0xb8, (byte) 0x2b,
            (byte) 0xb3, (byte) 0x30, (byte) 0x98, (byte) 0x65, (byte) 0xf5, (byte) 0x12, (byte) 0xab, (byte) 0x45,
            (byte) 0x78, (byte) 0x29, (byte) 0x87, (byte) 0xdc, (byte) 0x74, (byte) 0x07, (byte) 0x75, (byte) 0xd0,
            (byte) 0x68, (byte) 0xad, (byte) 0x85, (byte) 0x71, (byte) 0x08, (byte) 0xc2, (byte) 0x19, (byte) 0xf0,
            (byte) 0xf4, (byte) 0xca, (byte) 0x6e, (byte) 0xe1, (byte) 0xea, (byte) 0x86, (byte) 0xe6, (byte) 0x21,
            (byte) 0x76};
    public final static byte[] sm2PublicKey = new byte[]{
            (byte) 0x30, (byte) 0x59, (byte) 0x30, (byte) 0x13, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86,
            (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x02, (byte) 0x01, (byte) 0x06, (byte) 0x08, (byte) 0x2a,
            (byte) 0x81, (byte) 0x1c, (byte) 0xcf, (byte) 0x55, (byte) 0x01, (byte) 0x82, (byte) 0x2d, (byte) 0x03,
            (byte) 0x42, (byte) 0x00, (byte) 0x04, (byte) 0xb1, (byte) 0x1e, (byte) 0x4c, (byte) 0x8c, (byte) 0xa9,
            (byte) 0x02, (byte) 0xf2, (byte) 0x8d, (byte) 0x8b, (byte) 0x98, (byte) 0xd2, (byte) 0xd0, (byte) 0xc4,
            (byte) 0xf1, (byte) 0x60, (byte) 0x91, (byte) 0xfb, (byte) 0x61, (byte) 0x62, (byte) 0x00, (byte) 0xcf,
            (byte) 0x93, (byte) 0x4e, (byte) 0x3f, (byte) 0xca, (byte) 0xfd, (byte) 0xf7, (byte) 0x9d, (byte) 0x76,
            (byte) 0xb8, (byte) 0x2b, (byte) 0xb3, (byte) 0x30, (byte) 0x98, (byte) 0x65, (byte) 0xf5, (byte) 0x12,
            (byte) 0xab, (byte) 0x45, (byte) 0x78, (byte) 0x29, (byte) 0x87, (byte) 0xdc, (byte) 0x74, (byte) 0x07,
            (byte) 0x75, (byte) 0xd0, (byte) 0x68, (byte) 0xad, (byte) 0x85, (byte) 0x71, (byte) 0x08, (byte) 0xc2,
            (byte) 0x19, (byte) 0xf0, (byte) 0xf4, (byte) 0xca, (byte) 0x6e, (byte) 0xe1, (byte) 0xea, (byte) 0x86,
            (byte) 0xe6, (byte) 0x21, (byte) 0x76};

    public final static byte[] key = {1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8};

    public final static byte[] iv = {1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8};

    public static final native boolean initJNIEnv(Context context);

    public static final native String genAesId(String sessionId, String timeStamp);

    public static final native String digestSM3(byte[] input);

    public static final native String signSM2WithPrivateKey(byte[] input, byte[] priKey);

    public static final native String decryptSM2WithPrivateKey(byte[] input, byte[] priKey);

    public static final native boolean verifySM2WithPublicKey(byte[] sign, byte[] original, byte[] pubKey);

    public static final native String encryptSM2WithPublicKey(byte[] input, byte[] pubKey);

    public static final native String encryptWithSM4(byte[] input, byte[] key,byte[] iv);

    public static final native String decryptWithSM4(byte[] input, byte[] key,byte[] iv);

}
