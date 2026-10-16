#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include "de_cryptearth_crypto_libtss_LibTss.h"
#include "libtss_jni.h"
#include "libtss.h"
JNIEXPORT jobject JNICALL Java_de_cryptearth_crypto_libtss_LibTss_dkgNew0(JNIEnv *env, jclass clazz, jint java_suite, jint java_self_id, jint java_max_signers, jint java_min_signers, jbyteArray java_session_id)
{
	(void)clazz;
	if(java_suite<0||java_suite>UINT8_MAX||java_self_id<0||java_self_id>UINT16_MAX||java_max_signers<0||java_max_signers>UINT16_MAX||java_min_signers<0||java_min_signers>UINT16_MAX)
	{
		jclass exception_class = (*env)->FindClass(
		env, "java/lang/IllegalArgumentException");
		if(exception_class!=NULL)
		{
			(*env)->ThrowNew(env, exception_class, "DKG argument is outside its native integer range");
		}
		return NULL;
	}
	jbyte *session_id;
	size_t session_id_len;
	if(!jni_get_byte_array(env, java_session_id, &session_id, &session_id_len))
	{
		return NULL;
	}
	TssHandle session = 0;
	TssBuffer messages={.data = NULL, .len=0};
	TssStatus status=tss_dkg_new((uint8_t)java_suite, (uint16_t)java_self_id, (uint16_t)java_max_signers, (uint16_t)java_min_signers, (const uint8_t *)session_id, session_id_len, &session, &messages);
	jni_release_byte_array(env, java_session_id, session_id);
	if(status!=TSS_OK)
	{
		jni_throw_tss_exception(env, status);
		return NULL;
	}
	jbyteArray java_messages=jni_consume_buffer(env, &messages);
	if(java_messages==NULL)
	{
		tss_session_free(session);
		return NULL;
	}
	jclass result_class=(*env)->FindClass(env, "de/cryptearth/crypto/libtss/DkgNewResult0");
	if(result_class==NULL)
	{
		tss_session_free(session);
		return NULL;
	}
	jmethodID constructor=(*env)->GetMethodID(env, result_class, "<init>", "(J[B)V");
	if(constructor==NULL)
	{
		tss_session_free(session);
		return NULL;
	}
	jobject result=(*env)->NewObject(env, result_class, constructor, (jlong)session, java_messages);
	if(result==NULL)
	{
		tss_session_free(session);
		return NULL;
	}
	return result;
}
JNIEXPORT jobject JNICALL Java_de_cryptearth_crypto_libtss_LibTss_dkgNext0(JNIEnv *env, jclass clazz, jlong java_session, jbyteArray java_messages)
{
	(void)clazz;
	jbyte *messages_data;
	size_t messages_len;
	if(!jni_get_byte_array(env, java_messages, &messages_data, &messages_len))
	{
		return NULL;
	}
	TssSlice messages={.data=(const uint8_t *)messages_data, .len=messages_len};
	TssHandle key_share=0;
	TssBuffer pubkey_package={.data=NULL, .len=0};
	TssBuffer outbound={.data=NULL, .len=0};
	bool complete=false;
	TssStatus status=tss_dkg_next((TssHandle)java_session, messages, &key_share, &pubkey_package, &outbound, &complete);
	jni_release_byte_array(env, java_messages, messages_data);
	if(status!=TSS_OK)
	{
		if(pubkey_package.data!=NULL||pubkey_package.len!=0)
		{
			tss_buffer_free(&pubkey_package);
		}
		if(outbound.data!=NULL||outbound.len!=0)
		{
			tss_buffer_free(&outbound);
		}
		if(key_share!=0)
		{
			tss_handle_free(key_share);
		}
		jni_throw_tss_exception(env, status);
		return NULL;
	}
	jbyteArray java_pubkey_package=jni_consume_buffer(env, &pubkey_package);
	if(java_pubkey_package==NULL)
	{
		if(outbound.data!=NULL||outbound.len!=0)
		{
			tss_buffer_free(&outbound);
		}
		if(key_share!=0)
		{
			tss_handle_free(key_share);
		}
		return NULL;
	}
	jbyteArray java_outbound=jni_consume_buffer(env, &outbound);
	if(java_outbound==NULL)
	{
		if(key_share!=0)
		{
			tss_handle_free(key_share);
		}
		return NULL;
	}
	jclass result_class=(*env)->FindClass(env, "de/cryptearth/crypto/libtss/DkgNextResult0");
	if(result_class==NULL)
	{
		if(key_share!=0)
		{
			tss_handle_free(key_share);
		}
		return NULL;
	}
	jmethodID constructor=(*env)->GetMethodID(env, result_class, "<init>", "(J[B[BZ)V");
	if(constructor==NULL)
	{
		if(key_share!=0)
		{
			tss_handle_free(key_share);
		}
		return NULL;
	}
	jobject result=(*env)->NewObject(env, result_class, constructor, (jlong)key_share, java_pubkey_package, java_outbound, (jboolean)complete);
	if(result==NULL)
	{
		if(key_share!=0){
			tss_handle_free(key_share);
		}
		return NULL;
	}
	return result;
}
