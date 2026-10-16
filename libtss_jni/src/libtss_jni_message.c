#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include "de_cryptearth_crypto_libtss_LibTss.h"
#include "libtss_jni.h"
#include "libtss.h"
JNIEXPORT jint JNICALL Java_de_cryptearth_crypto_libtss_LibTss_messageCount0(JNIEnv *env, jclass clazz, jbyteArray java_messages)
{
	(void)clazz;
	jbyte *data;
	size_t len;
	if(!jni_get_byte_array(env, java_messages, &data, &len))
	{
		return 0;
	}
	TssSlice messages={.data=(const uint8_t *)data, .len=len};
	size_t count=tss_message_count(messages);
	jni_release_byte_array(env, java_messages, data);
	if(count>INT32_MAX)
	{
		jclass exception_class=(*env)->FindClass(env, "java/lang/IllegalStateException");
		if(exception_class!=NULL)
		{
			(*env)->ThrowNew(env, exception_class, "message count is too large for Java int");
		}
		return 0;
	}
	return (jint)count;
}
JNIEXPORT jobject JNICALL Java_de_cryptearth_crypto_libtss_LibTss_messageAt0(JNIEnv *env, jclass clazz, jbyteArray java_messages, jint java_index)
{
	(void)clazz;
	if(java_index<0)
	{
		jclass exception_class=(*env)->FindClass(env, "java/lang/IndexOutOfBoundsException");
		if(exception_class!=NULL)
		{
			(*env)->ThrowNew(env, exception_class, "message index must not be negative");
		}
		return NULL;
	}
	jbyte *data;
	size_t len;
	if(!jni_get_byte_array(env, java_messages, &data, &len))
	{
		return NULL;
	}
	TssSlice messages={.data=(const uint8_t *)data, .len=len};
	uint16_t from;
	uint16_t to;
	TssSlice message;
	TssStatus status=tss_message_at(messages, (size_t)java_index, &from, &to, &message);
	if(status!=TSS_OK)
	{
		jni_release_byte_array(env, java_messages, data);
		jni_throw_tss_exception(env, status);
		return NULL;
	}
	jbyteArray java_data=jni_slice_to_byte_array(env, message);
	jni_release_byte_array(env, java_messages, data);
	if(java_data==NULL)
	{
		return NULL;
	}
	jclass message_class=(*env)->FindClass(env, "de/cryptearth/crypto/libtss/Message");
	if(message_class==NULL)
	{
		return NULL;
	}
	jmethodID constructor=(*env)->GetMethodID(env, message_class, "<init>", "(II[B)V");
	if(constructor==NULL)
	{
		return NULL;
	}
	return (*env)->NewObject(env, message_class, constructor, (jint)from, (jint)to, java_data);
}
JNIEXPORT jbyteArray JNICALL Java_de_cryptearth_crypto_libtss_LibTss_messageBuild0(JNIEnv *env, jclass clazz, jbyteArray java_messages, jint java_from, jint java_to, jbyteArray java_data)
{
	(void)clazz;
	if(java_from<0||java_from>UINT16_MAX||java_to<0||java_to>UINT16_MAX)
	{
		jclass exception_class=(*env)->FindClass(env, "java/lang/IllegalArgumentException");
		if(exception_class!=NULL)
		{
			(*env)->ThrowNew(env, exception_class, "message participant ID must fit into uint16_t");
		}
		return NULL;
	}
	jbyte *messages=NULL;
	size_t messages_len=0;
	if(java_messages!=NULL)
	{
		if(!jni_get_byte_array(env, java_messages, &messages, &messages_len))
		{
			return NULL;
		}
	}
	jbyte *data;
	size_t data_len;
	if(!jni_get_byte_array(env, java_data, &data, &data_len))
	{
		if(messages!=NULL)
		{
			jni_release_byte_array(env, java_messages, messages);
		}
		return NULL;
	}
	TssBuffer buffer={.data=NULL, .len=0};
	if(messages_len!=0)
	{
		buffer.data=malloc(messages_len);
		if(buffer.data==NULL)
		{
			jni_release_byte_array(env, java_data, data);
			if(messages!=NULL)
			{
				jni_release_byte_array(env, java_messages, messages);
			}
			jclass exception_class=(*env)->FindClass(env, "java/lang/OutOfMemoryError");
			if(exception_class!=NULL)
			{
				(*env)->ThrowNew(env, exception_class, "could not allocate message buffer");
			}
			return NULL;
		}
		memcpy(buffer.data, messages, messages_len);
		buffer.len=messages_len;
	}
	TssStatus status = tss_message_build(&buffer, (uint16_t)java_from, (uint16_t)java_to, (const uint8_t *)data, data_len);
	jni_release_byte_array(env, java_data, data);
	if(messages!=NULL)
	{
		jni_release_byte_array(env, java_messages, messages);
	}
	if(status!=TSS_OK)
	{
		tss_buffer_free(&buffer);
		jni_throw_tss_exception(env, status);
		return NULL;
	}
	return jni_consume_buffer(env, &buffer);
}
