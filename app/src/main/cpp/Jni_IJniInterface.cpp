#include <jni.h>
#include <string.h>
#include "GTJAXHexCode.h"
#include "GTCryptUtil.h"
#include <stdlib.h>
#include <android/log.h>

#define GTJAJniLog_printf(...) __android_log_print(ANDROID_LOG_VERBOSE, "gtjaCommonJni", __VA_ARGS__)

static JavaVM *pJVM = NULL;
bool mHasInit = false;
const char *f_word = "gtjaGMAS@990818";
const char originalSign[] = "D8981DBA76FBB6189DA48EA5A4973589D5D89E5D";

char *convertJByteArrayToChars(JNIEnv *env, jbyteArray bytearray) {
    char *chars = NULL;
    jbyte *bytes;
    bytes = env->GetByteArrayElements(bytearray, 0);
    int chars_len = env->GetArrayLength(bytearray);
    chars = new char[chars_len + 1];
    memset(chars, 0, chars_len + 1);
    memcpy(chars, bytes, chars_len);
    chars[chars_len] = 0;
    env->ReleaseByteArrayElements(bytearray, bytes, 0);
    return chars;
}

bool checkAppValid(JNIEnv *pEnv, jobject activity) {

    jclass cls = pEnv->FindClass("com/guotai/dazhihui/BuildConfig");
    //防止找不到buildconfig类
    if (pEnv->ExceptionCheck()) {
        GTJAJniLog_printf("find check signature exception");
        pEnv->ExceptionDescribe();
        pEnv->ExceptionClear();//清除异常
        return false;
    }

    jfieldID field = pEnv->GetStaticFieldID(cls, "ANTI_DEBUG", "Z");
    jboolean antiFlag = pEnv->GetStaticBooleanField(cls, field);
    //防止在buildconfig类中找不到anti_debug变量
    if (pEnv->ExceptionCheck()) {
        GTJAJniLog_printf("find check signature exception");
        pEnv->ExceptionDescribe();
        pEnv->ExceptionClear();//清除异常
        return false;
    }

    if (antiFlag == JNI_FALSE) {
        pEnv->DeleteLocalRef(cls);
        return true;
    }

    cls = pEnv->FindClass("android/app/Activity");
    jmethodID methodId = pEnv->GetMethodID(cls, "getPackageManager",
                                           "()Landroid/content/pm/PackageManager;");
    jobject pm = pEnv->CallObjectMethod(activity, methodId);
    jclass atcls = pEnv->FindClass("android/app/ActivityThread");
    jmethodID atmethodId = pEnv->GetStaticMethodID(atcls, "currentPackageName",
                                                   "()Ljava/lang/String;");
    jstring packageName = (jstring) pEnv->CallStaticObjectMethod(atcls, atmethodId);
    pEnv->DeleteLocalRef(atcls);

    //split for push service, which running in another process.
    cls = pEnv->FindClass("java/lang/String");
    methodId = pEnv->GetMethodID(cls, "split",
                                 "(Ljava/lang/String;)[Ljava/lang/String;");
    jstring splitSign = pEnv->NewStringUTF(":");
    jobjectArray splitResult = (jobjectArray) pEnv->CallObjectMethod(
            packageName, methodId, splitSign);
    packageName = (jstring) pEnv->GetObjectArrayElement(splitResult, 0);

    cls = pEnv->FindClass("android/content/pm/PackageManager");
    methodId = pEnv->GetMethodID(cls, "getPackageInfo",
                                 "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");

    field = pEnv->GetStaticFieldID(cls, "GET_SIGNATURES", "I");
    jint v = pEnv->GetStaticIntField(cls, field);

    jobject pkgInfo = pEnv->CallObjectMethod(pm, methodId, packageName, v);
    cls = pEnv->FindClass("android/content/pm/PackageInfo");
    field = pEnv->GetFieldID(cls, "signatures",
                             "[Landroid/content/pm/Signature;");
    jobjectArray objectArray = (jobjectArray) pEnv->GetObjectField(pkgInfo, field);
    jobject signatureObject = pEnv->GetObjectArrayElement(
            objectArray, 0);
    pEnv->DeleteLocalRef(pm);
    pEnv->DeleteLocalRef(pkgInfo);

    //Signature.toByteArray()
    jclass signatureClass = pEnv->GetObjectClass(signatureObject);
    methodId = pEnv->GetMethodID(signatureClass, "toByteArray", "()[B");
    jbyteArray signatureByte = (jbyteArray) pEnv->CallObjectMethod(
            signatureObject, methodId);
    pEnv->DeleteLocalRef(signatureObject);

    //MessageDigest.getInstance("SHA1")
    jclass message_digest_class = pEnv->FindClass(
            "java/security/MessageDigest");
    methodId = pEnv->GetStaticMethodID(message_digest_class, "getInstance",
                                       "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    jstring sha1_jstring = pEnv->NewStringUTF("SHA1");
    jobject sha1_digest = pEnv->CallStaticObjectMethod(message_digest_class,
                                                       methodId, sha1_jstring);

    //sha1.digest (certByte)
    methodId = pEnv->GetMethodID(message_digest_class, "digest", "([B)[B");
    jbyteArray sha1_byte = (jbyteArray) pEnv->CallObjectMethod(sha1_digest, methodId,
                                                               signatureByte);
    pEnv->DeleteLocalRef(cls);
    pEnv->DeleteLocalRef(signatureClass);
    pEnv->DeleteLocalRef(message_digest_class);
    pEnv->DeleteLocalRef(sha1_digest);

    //toHexString
    char *data = convertJByteArrayToChars(pEnv, sha1_byte);
    char *result = NULL;
    GTJAXHexDecode((const unsigned char *) data, strlen(data), &result);
    delete data;

    //compare
    if (strcmp(result, originalSign) == 0) {
        delete result;
        return JNI_TRUE;
    } else {
        delete result;
        return JNI_FALSE;
    }

}


void doInitialize(JNIEnv *pEnv) {
    if (pJVM == NULL) {
        pEnv->GetJavaVM(&pJVM);
    }
}

jboolean Jni_initJNIEnv(JNIEnv *pEnv, jclass msgFactoryClass, jobject p) {
    if (mHasInit) {
        return JNI_TRUE;
    }
    if (checkAppValid(pEnv, p)) {
        doInitialize(pEnv);
        mHasInit = true;
    }
    return JNI_TRUE;
}

jstring Jni_genAesId(JNIEnv *pEnv, jclass msgFactoryClass, jstring sessionId, jstring timeStamp) {
    if (!mHasInit) {
        return NULL;
    }

    if (NULL == sessionId) {
        return NULL;
    }

    if (NULL == timeStamp) {
        return NULL;
    }

    jstring jret = NULL;
    char *input = NULL;
    char *pOut = NULL;

    const char *pData = pEnv->GetStringUTFChars(sessionId, NULL);
    const char *pTimeStamp = pEnv->GetStringUTFChars(timeStamp, NULL);
    if (pData == NULL) {
        return NULL; /* OutOfMemoryError already thrown */
    }
    if (pTimeStamp == NULL) {
        return NULL; /* OutOfMemoryError already thrown */
    }

    int len = (int) (strlen(pData) + strlen(f_word) + strlen(pTimeStamp));
    input = (char *) malloc(sizeof(char) * (len + 1));
    if (input) {
        memset(input, 0x00, (size_t) len + 1);
    } else {
        pEnv->ReleaseStringUTFChars(sessionId, pData);
        pEnv->ReleaseStringUTFChars(timeStamp, pTimeStamp);
        return NULL;
    }
    strcat(input, pData);
    strcat(input, pTimeStamp);
    strcat(input, f_word);
    getMD5(input, &pOut);
    free(input);
    if (pOut) {
        jret = pEnv->NewStringUTF(pOut);
        free(pOut);
    }
    pEnv->ReleaseStringUTFChars(sessionId, pData);
    pEnv->ReleaseStringUTFChars(timeStamp, pTimeStamp);
    return jret;
}

/**
 * 使用国密SM3杂凑算法进行散列计算
 * @param pEnv
 * @param msgFactoryClass
 * @param input
 * @return
 */
jstring Jni_digestSM3(JNIEnv *pEnv, jclass msgFactoryClass, jbyteArray input) {
    if (!mHasInit) {
        return NULL;
    }

    if (NULL == input) {
        return NULL;
    }

    jstring jret = NULL;
    char *pOut = NULL;

    const unsigned char *pIn = (unsigned char *) pEnv->GetByteArrayElements(input, NULL);

    if (pIn == NULL) {
        return NULL; /* OutOfMemoryError already thrown */
    }

    int inputLen = pEnv->GetArrayLength(input);

    if (inputLen <= 0) {
        return NULL;
    }

    getSM3(pIn, inputLen, &pOut);

    if (pOut) {
        jret = pEnv->NewStringUTF(pOut);
        free(pOut);
    }
    pEnv->ReleaseByteArrayElements(input, (jbyte *) pIn, JNI_ABORT);
    return jret;
}


/**
 * 使用国密SM2非对称算法的私钥进行签名
 * @param pEnv
 * @param msgFactoryClass
 * @param input
 * @param priKey
 * @return
 */
jstring Jni_signSM2WithPrivateKey(JNIEnv *pEnv, jclass msgFactoryClass, jbyteArray input,
                                  jbyteArray priKey) {
    if (!mHasInit) {
        return NULL;
    }

    if (NULL == input) {
        return NULL;
    }
    if (NULL == priKey) {
        return NULL;
    }
    jstring jret = NULL;
    char *pOut = NULL;

    const unsigned char *pIn = (unsigned char *) pEnv->GetByteArrayElements(input, NULL);
    const unsigned char *pKey = (unsigned char *) pEnv->GetByteArrayElements(priKey, NULL);

    if (pIn == NULL) {
        return NULL; /* OutOfMemoryError already thrown */
    }
    if (pKey == NULL) {
        return NULL; /* OutOfMemoryError already thrown */
    }

    int inputLen = pEnv->GetArrayLength(input);

    if (inputLen <= 0) {
        return NULL;
    }

    int keyLen = pEnv->GetArrayLength(priKey);

    if (keyLen <= 0) {
        return NULL;
    }

    getSM2Sign(pIn, inputLen, pKey, keyLen, &pOut);

    if (pOut) {
        jret = pEnv->NewStringUTF(pOut);
        free(pOut);
    }
    pEnv->ReleaseByteArrayElements(input, (jbyte *) pIn, JNI_ABORT);
    pEnv->ReleaseByteArrayElements(priKey, (jbyte *) pKey, JNI_ABORT);
    return jret;
}

/**
 * 使用国密SM2非对称算法私钥进行解密
 * @param pEnv
 * @param msgFactoryClass
 * @param input
 * @param priKey
 * @return
 */
jstring Jni_decryptSM2WithPrivateKey(JNIEnv *pEnv, jclass msgFactoryClass, jbyteArray input,
                                     jbyteArray priKey) {
    if (!mHasInit) {
        return JNI_FALSE;
    }

    if (NULL == input) {
        return JNI_FALSE;
    }
    jstring jret = NULL;
    char *pOut = NULL;
    const unsigned char *pIn = (unsigned char *) pEnv->GetByteArrayElements(input, NULL);
    const unsigned char *pPriKey = (unsigned char *) pEnv->GetByteArrayElements(priKey, NULL);
    if (pIn == NULL) {
        return JNI_FALSE;
    }

    if (pPriKey == NULL) {
        return JNI_FALSE;
    }
    int inLen = pEnv->GetArrayLength(input);

    if (inLen <= 0) {
        return JNI_FALSE;
    }

    int priKeyLen = pEnv->GetArrayLength(priKey);

    if (priKeyLen <= 0) {
        return JNI_FALSE;
    }

    getSM2Decrypt(pIn, inLen, pPriKey, priKeyLen, &pOut);

    if (pOut) {
        jret = pEnv->NewStringUTF(pOut);
        free(pOut);
    }
    pEnv->ReleaseByteArrayElements(input, (jbyte *) pIn, JNI_ABORT);
    pEnv->ReleaseByteArrayElements(priKey, (jbyte *) pPriKey, JNI_ABORT);
    return jret;
}

/**
 * 使用国密SM2非对称算法公钥进行验签
 * @param pEnv
 * @param msgFactoryClass
 * @param input
 * @param pubKey
 * @return
 */
jboolean Jni_verifySM2WithPublicKey(JNIEnv *pEnv, jclass msgFactoryClass, jbyteArray sign,
                                    jbyteArray original, jbyteArray pubKey) {
    if (!mHasInit) {
        return JNI_FALSE;
    }

    if (NULL == sign) {
        return JNI_FALSE;
    }

    const unsigned char *pSigned = (unsigned char *) pEnv->GetByteArrayElements(sign, NULL);
    const unsigned char *pOriginal = (unsigned char *) pEnv->GetByteArrayElements(original, NULL);
    const unsigned char *pPubKey = (unsigned char *) pEnv->GetByteArrayElements(pubKey, NULL);
    if (pSigned == NULL) {
        return JNI_FALSE;
    }
    if (pOriginal == NULL) {
        return JNI_FALSE;
    }
    if (pPubKey == NULL) {
        return JNI_FALSE;
    }
    int signLen = pEnv->GetArrayLength(sign);

    if (signLen <= 0) {
        return JNI_FALSE;
    }
    int originalLen = pEnv->GetArrayLength(original);

    if (originalLen <= 0) {
        return JNI_FALSE;
    }
    int pubKeyLen = pEnv->GetArrayLength(pubKey);

    if (pubKeyLen <= 0) {
        return JNI_FALSE;
    }

    if (getSM2Verify(pSigned, signLen, pOriginal, originalLen, pPubKey, pubKeyLen)) {
        pEnv->ReleaseByteArrayElements(sign, (jbyte *) pSigned, JNI_ABORT);
        pEnv->ReleaseByteArrayElements(original, (jbyte *) pOriginal, JNI_ABORT);
        pEnv->ReleaseByteArrayElements(pubKey, (jbyte *) pPubKey, JNI_ABORT);
        return JNI_TRUE;
    } else {
        pEnv->ReleaseByteArrayElements(sign, (jbyte *) pSigned, JNI_ABORT);
        pEnv->ReleaseByteArrayElements(original, (jbyte *) pOriginal, JNI_ABORT);
        pEnv->ReleaseByteArrayElements(pubKey, (jbyte *) pPubKey, JNI_ABORT);
        return JNI_FALSE;
    }
}

/**
 * 使用国密SM2非对称算法公钥进行加密
 * @param pEnv
 * @param msgFactoryClass
 * @param input
 * @param pubKey
 * @return
 */
jstring Jni_encryptSM2WithPublicKey(JNIEnv *pEnv, jclass msgFactoryClass, jbyteArray input,
                                    jbyteArray pubKey) {
    if (!mHasInit) {
        return JNI_FALSE;
    }

    if (NULL == input) {
        return JNI_FALSE;
    }
    jstring jret = NULL;
    char *pOut = NULL;
    const unsigned char *pIn = (unsigned char *) pEnv->GetByteArrayElements(input, NULL);
    const unsigned char *pPubKey = (unsigned char *) pEnv->GetByteArrayElements(pubKey, NULL);
    if (pIn == NULL) {
        return JNI_FALSE;
    }

    if (pPubKey == NULL) {
        return JNI_FALSE;
    }
    int inLen = pEnv->GetArrayLength(input);

    if (inLen <= 0) {
        return JNI_FALSE;
    }

    int pubKeyLen = pEnv->GetArrayLength(pubKey);

    if (pubKeyLen <= 0) {
        return JNI_FALSE;
    }

    getSM2Encrypt(pIn, inLen, pPubKey, pubKeyLen, &pOut);

    if (pOut) {
        jret = pEnv->NewStringUTF(pOut);
        free(pOut);
    }
    pEnv->ReleaseByteArrayElements(input, (jbyte *) pIn, JNI_ABORT);
    pEnv->ReleaseByteArrayElements(pubKey, (jbyte *) pPubKey, JNI_ABORT);
    return jret;
}

/**
 * 使用国密SM2非对称算法公钥进行加密
 * @param pEnv
 * @param msgFactoryClass
 * @param input
 * @param pubKey
 * @return
 */
jstring Jni_encryptWithSM4(JNIEnv *pEnv, jclass msgFactoryClass, jbyteArray input, jbyteArray iv,
                           jbyteArray key) {
    if (!mHasInit) {
        return JNI_FALSE;
    }

    if (NULL == input) {
        return JNI_FALSE;
    }
    jstring jret = NULL;
    char *pOut = NULL;
    const unsigned char *pIn = (unsigned char *) pEnv->GetByteArrayElements(input, NULL);
    const unsigned char *pIv = (unsigned char *) pEnv->GetByteArrayElements(iv, NULL);
    const unsigned char *pKey = (unsigned char *) pEnv->GetByteArrayElements(key, NULL);
    if (pIn == NULL) {
        return JNI_FALSE;
    }
    if (pIv == NULL) {
        return JNI_FALSE;
    }
    if (pKey == NULL) {
        return JNI_FALSE;
    }
    int inLen = pEnv->GetArrayLength(input);

    if (inLen <= 0) {
        return JNI_FALSE;
    }

    int ivLen = pEnv->GetArrayLength(iv);

    if (ivLen <= 0) {
        return JNI_FALSE;
    }
    int keyLen = pEnv->GetArrayLength(key);

    if (keyLen <= 0) {
        return JNI_FALSE;
    }

    getSM4Encrypt(pIn, inLen, pIv, ivLen, pKey, keyLen, &pOut);

    if (pOut) {
        jret = pEnv->NewStringUTF(pOut);
        free(pOut);
    }
    pEnv->ReleaseByteArrayElements(input, (jbyte *) pIn, JNI_ABORT);
    pEnv->ReleaseByteArrayElements(iv, (jbyte *) pIv, JNI_ABORT);
    pEnv->ReleaseByteArrayElements(key, (jbyte *) pKey, JNI_ABORT);
    return jret;
}


/**
 * 使用国密SM4对称算法公钥进行解密
 * @param pEnv
 * @param msgFactoryClass
 * @param input
 * @param pubKey
 * @return
 */
jstring Jni_decryptWithSM4(JNIEnv *pEnv, jclass msgFactoryClass, jbyteArray input, jbyteArray iv,
                           jbyteArray key) {
    if (!mHasInit) {
        return JNI_FALSE;
    }

    if (NULL == input) {
        return JNI_FALSE;
    }
    jstring jret = NULL;
    char *pOut = NULL;
    const unsigned char *pIn = (unsigned char *) pEnv->GetByteArrayElements(input, NULL);
    const unsigned char *pIv = (unsigned char *) pEnv->GetByteArrayElements(iv, NULL);
    const unsigned char *pKey = (unsigned char *) pEnv->GetByteArrayElements(key, NULL);
    if (pIn == NULL) {
        return JNI_FALSE;
    }
    if (pIv == NULL) {
        return JNI_FALSE;
    }
    if (pKey == NULL) {
        return JNI_FALSE;
    }
    int inLen = pEnv->GetArrayLength(input);

    if (inLen <= 0) {
        return JNI_FALSE;
    }

    int ivLen = pEnv->GetArrayLength(iv);

    if (ivLen <= 0) {
        return JNI_FALSE;
    }
    int keyLen = pEnv->GetArrayLength(key);

    if (keyLen <= 0) {
        return JNI_FALSE;
    }

    getSM4Decrypt(pIn, inLen, pIv, ivLen, pKey, keyLen, &pOut);

    if (pOut) {
        jret = pEnv->NewStringUTF(pOut);
        free(pOut);
    }
    pEnv->ReleaseByteArrayElements(input, (jbyte *) pIn, JNI_ABORT);
    pEnv->ReleaseByteArrayElements(iv, (jbyte *) pIv, JNI_ABORT);
    pEnv->ReleaseByteArrayElements(key, (jbyte *) pKey, JNI_ABORT);
    return jret;
}

static JNINativeMethod gMethods[] =
        {
                {"initJNIEnv",               "(Landroid/content/Context;)Z",
                        (void *) Jni_initJNIEnv},
                {"genAesId",                 "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                        (void *) Jni_genAesId},
                {"digestSM3",                "([B)Ljava/lang/String;",
                        (void *) Jni_digestSM3},
                {"signSM2WithPrivateKey",    "([B[B)Ljava/lang/String;",
                        (void *) Jni_signSM2WithPrivateKey},
                {"decryptSM2WithPrivateKey", "([B[B)Ljava/lang/String;",
                        (void *) Jni_decryptSM2WithPrivateKey},
                {"verifySM2WithPublicKey",   "([B[B[B)Z",
                        (void *) Jni_verifySM2WithPublicKey},
                {"encryptSM2WithPublicKey",  "([B[B)Ljava/lang/String;",
                        (void *) Jni_encryptSM2WithPublicKey},
                {"encryptWithSM4",           "([B[B[B)Ljava/lang/String;",
                        (void *) Jni_encryptWithSM4},
                {"decryptWithSM4",           "([B[B[B)Ljava/lang/String;",
                        (void *) Jni_decryptWithSM4}
        };

static int registerNativeMethods(JNIEnv *env, const char *className,
                                 JNINativeMethod *gMethods, int numMethods) {
    jclass clazz;
    clazz = env->FindClass(className);
    if (clazz == NULL) {
        return JNI_FALSE;
    }
    if (env->RegisterNatives(clazz, gMethods, numMethods) < 0) {
        return JNI_FALSE;
    }

    return JNI_TRUE;
}

static int registerNatives(JNIEnv *env) {
    const char *kClassName = "com/gtja/common/jni/IJniInterface";
    return registerNativeMethods(env, kClassName, gMethods,
                                 sizeof(gMethods) / sizeof(gMethods[0]));
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    jint result = -1;

    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return -1;
    }

    if (!registerNatives(env)) {
        return -1;
    }
    result = JNI_VERSION_1_6;

    return result;
}
