#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include "de_cryptearth_crypto_libtss_LibTss.h"
#include "libtss_jni.h"
#include "libtss.h"
JNIEXPORT jobject JNICALL Java_de_cryptearth_crypto_libtss_LibTss_signNew0(JNIEnv *env, jclass clazz, jlong java_key_share, jbyteArray java_hash, jintArray java_counterparties, jbyteArray java_sign_id)
{
	(void)clazz;
	if(java_counterparties==NULL)
	{
		jclass exception_class=(*env)->FindClass(env, "java/lang/NullPointerException");
		if(exception_class!=NULL)
		{
			(*env)->ThrowNew(env, exception_class, "counterparties must not be null");
		}
		return NULL;
	}
	if(java_key_share==0)
	{
		jclass exception_class=(*env)->FindClass(env, "java/lang/IllegalArgumentException");
		if(exception_class!=NULL)
		{
			(*env)->ThrowNew(env, exception_class, "key share handle must not be zero");
		}
		return NULL;
	}
	jbyte *hash_data;
	size_t hash_len;
	if(!jni_get_byte_array(env, java_hash, &hash_data, &hash_len))
	{
		return NULL;
	}
	TssSlice hash={.data=(const uint8_t *)hash_data, .len=hash_len};
	jsize counterparties_len=(*env)->GetArrayLength(env, java_counterparties);
	jint *java_counterparties_data=(*env)->GetIntArrayElements(env, java_counterparties, NULL);
	if(java_counterparties_data==NULL)
	{
		jni_release_byte_array(env, java_hash, hash_data);
		return NULL;
	}
	uint16_t *counterparties=NULL;
	if(counterparties_len>0)
	{
		counterparties=malloc((size_t)counterparties_len*sizeof(uint16_t));
		if(counterparties==NULL)
		{
			(*env)->ReleaseIntArrayElements(env, java_counterparties, java_counterparties_data, JNI_ABORT);
			jni_release_byte_array(env, java_hash, hash_data);
			jclass exception_class=(*env)->FindClass(env, "java/lang/OutOfMemoryError");
			if(exception_class!=NULL)
			{
				(*env)->ThrowNew(env, exception_class, "could not allocate counterparties");
			}
			return NULL;
		}
		for(jsize i=0; i<counterparties_len; i++)
		{
			if(java_counterparties_data[i]<0||java_counterparties_data[i]>UINT16_MAX)
			{
				free(counterparties);
				(*env)->ReleaseIntArrayElements(env, java_counterparties, java_counterparties_data, JNI_ABORT);
				jni_release_byte_array(env, java_hash, hash_data);
				jclass exception_class=(*env)->FindClass(env, "java/lang/IllegalArgumentException");
				if(exception_class!=NULL)
				{
					(*env)->ThrowNew(env, exception_class, "counterparty ID must fit into uint16_t");
				}
				return NULL;
			}
			counterparties[i] =
			(uint16_t)java_counterparties_data[i];
		}
	}
	jbyte *sign_id_data;
	size_t sign_id_len;
	if(!jni_get_byte_array(env, java_sign_id, &sign_id_data, &sign_id_len))
	{
		free(counterparties);
		(*env)->ReleaseIntArrayElements(env, java_counterparties, java_counterparties_data, JNI_ABORT);
		jni_release_byte_array(env, java_hash, hash_data);
		return NULL;
	}
	TssHandle session=0;
	TssBuffer outbound={.data=NULL, .len=0};
	TssStatus status=tss_sign_new((TssHandle)java_key_share, hash, counterparties, (size_t)counterparties_len, (const uint8_t *)sign_id_data, sign_id_len, &session, &outbound);
	jni_release_byte_array(env, java_sign_id, sign_id_data);
	(*env)->ReleaseIntArrayElements(env, java_counterparties, java_counterparties_data, JNI_ABORT);
	free(counterparties);
	jni_release_byte_array(env, java_hash, hash_data);
	if(status!=TSS_OK)
	{
		jni_throw_tss_exception(env, status);
		return NULL;
	}
	jbyteArray java_outbound=jni_consume_buffer(env, &outbound);
	if(java_outbound==NULL)
	{
		tss_session_free(session);
		return NULL;
	}
	jclass result_class=(*env)->FindClass(env, "de/cryptearth/crypto/libtss/SignNewResult0");
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
	jobject result=(*env)->NewObject(env, result_class, constructor, (jlong)session, java_outbound);
	if(result==NULL)
	{
		tss_session_free(session);
		return NULL;
	}
	return result;
}
JNIEXPORT jobject JNICALL Java_de_cryptearth_crypto_libtss_LibTss_signNext0(JNIEnv *env, jclass clazz, jlong java_session, jbyteArray java_messages)
{
	(void)clazz;
	jbyte *messages_data;
	size_t messages_len;
	if(!jni_get_byte_array(env, java_messages, &messages_data, &messages_len))
	{
		return NULL;
	}
	TssSlice messages={.data=(const uint8_t *)messages_data, .len=messages_len};
	TssBuffer signature={.data=NULL, .len=0};
	TssBuffer outbound={.data=NULL, .len=0};
	bool complete=false;
	TssStatus status=tss_sign_next((TssHandle)java_session, messages, &signature, &outbound, &complete);
	jni_release_byte_array(env, java_messages, messages_data);
	if(status!=TSS_OK)
	{
		if(signature.data!=NULL||signature.len!=0)
		{
			tss_buffer_free(&signature);
		}
		if(outbound.data!=NULL||outbound.len!=0)
		{
			tss_buffer_free(&outbound);
		}
		jni_throw_tss_exception(env, status);
		return NULL;
	}
	jbyteArray java_signature=jni_consume_buffer(env, &signature);
	if(java_signature==NULL)
	{
		tss_buffer_free(&outbound);
		return NULL;
	}
	jbyteArray java_outbound=jni_consume_buffer(env, &outbound);
	if(java_outbound==NULL)
	{
		return NULL;
	}
	jclass result_class=(*env)->FindClass(env, "de/cryptearth/crypto/libtss/SignNextResult0");
	if(result_class==NULL)
	{
		return NULL;
	}
	jmethodID constructor=(*env)->GetMethodID(env, result_class,"<init>", "([B[BZ)V");
	if(constructor==NULL)
	{
		return NULL;
	}
	return (*env)->NewObject(env, result_class, constructor, java_signature, java_outbound, (jboolean)complete);
}
