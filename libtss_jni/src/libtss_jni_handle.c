#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include "de_cryptearth_crypto_libtss_LibTss.h"
#include "libtss_jni.h"
#include "libtss.h"
JNIEXPORT jbyteArray JNICALL Java_de_cryptearth_crypto_libtss_LibTss_handleExport0(JNIEnv *env, jclass clazz, jlong handle)
{
	(void)clazz;
	TssBuffer out={.data=NULL, .len=0};
	TssStatus status=tss_handle_export((TssHandle)handle, &out);
	if(status!=TSS_OK)
	{
		jni_throw_tss_exception(env, status);
		return NULL;
	}
	return jni_consume_buffer(env, &out);
}
JNIEXPORT jbyteArray JNICALL Java_de_cryptearth_crypto_libtss_LibTss_handleGroupKey0(JNIEnv *env, jclass clazz, jlong handle)
{
	(void)clazz;
	TssBuffer out={.data=NULL, .len=0};
	TssStatus status=tss_handle_group_key((TssHandle)handle, &out);
	if(status!=TSS_OK)
	{
		jni_throw_tss_exception(env, status);
		return NULL;
	}
	return jni_consume_buffer(env, &out);
}
JNIEXPORT jbyteArray JNICALL Java_de_cryptearth_crypto_libtss_LibTss_handlePubkeyPackage0(JNIEnv *env, jclass clazz, jlong handle)
{
	(void)clazz;
	TssBuffer out={.data=NULL, .len=0};
	TssStatus status=tss_handle_pubkey_package((TssHandle)handle, &out);
	if(status!=TSS_OK)
	{
		jni_throw_tss_exception(env, status);
		return NULL;
	}
	return jni_consume_buffer(env, &out);
}
JNIEXPORT jlong JNICALL Java_de_cryptearth_crypto_libtss_LibTss_handleImport0(JNIEnv *env, jclass clazz, jbyteArray java_data, jint suite)
{
	(void)clazz;
	jbyte *data;
	size_t data_len;
	if (!jni_get_byte_array(env, java_data, &data, &data_len))
	{
		return 0;
	}
	TssHandle handle=0;
	TssStatus status=tss_handle_import((const uint8_t *)data, data_len, (uint8_t)suite, &handle);
	jni_release_byte_array(env, java_data, data);
	if(status!=TSS_OK)
	{
		jni_throw_tss_exception(env, status);
		return 0;
	}
	return (jlong)handle;
}
