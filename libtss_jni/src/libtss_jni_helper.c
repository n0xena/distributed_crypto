#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include "de_cryptearth_crypto_libtss_LibTss.h"
#include "libtss_jni.h"
#include "libtss.h"
bool jni_get_byte_array(JNIEnv *env, jbyteArray array, jbyte **data, size_t *len)
{
	if(array==NULL)
	{
		jclass exception_class=(*env)->FindClass(env, "java/lang/NullPointerException");
		if(exception_class!=NULL)
		{
			(*env)->ThrowNew(env, exception_class, "byte array must not be null");
		}
		return false;
	}
	jsize java_len=(*env)->GetArrayLength(env, array);
	*data=(*env)->GetByteArrayElements(env, array, NULL);
	if(*data==NULL)
	{
		return false;
	}
	*len=(size_t)java_len;
	return true;
}
void jni_release_byte_array(JNIEnv *env, jbyteArray array, jbyte *data)
{
	(*env)->ReleaseByteArrayElements(env, array, data, JNI_ABORT);
}
jbyteArray jni_buffer_to_byte_array(JNIEnv *env, const TssBuffer *buffer)
{
	if(buffer->len>INT32_MAX)
	{
		jclass exception_class = (*env)->FindClass(env, "java/lang/IllegalStateException");
		if(exception_class!=NULL)
		{
			(*env)->ThrowNew(env, exception_class, "TssBuffer is too large for a Java byte array");
		}
		return NULL;
	}
	jbyteArray result=(*env)->NewByteArray(env, (jsize)buffer->len);
	if(result==NULL)
	{
		return NULL;
	}
	if(buffer->len!=0)
	{
		(*env)->SetByteArrayRegion(env, result, 0, (jsize)buffer->len, (const jbyte *)buffer->data);
		if((*env)->ExceptionCheck(env))
		{
			return NULL;
		}
	}
	return result;
}
jbyteArray jni_slice_to_byte_array(JNIEnv *env, TssSlice slice)
{
	if(slice.len>INT32_MAX)
	{
		jclass exception_class=(*env)->FindClass(env, "java/lang/IllegalStateException");
		if(exception_class!=NULL)
		{
			(*env)->ThrowNew(env, exception_class, "TssSlice is too large for a Java byte array");
		}
		return NULL;
	}
	jbyteArray result=(*env)->NewByteArray(env, (jsize)slice.len);
	if(result==NULL)
	{
		return NULL;
	}
	if(slice.len!=0)
	{
		(*env)->SetByteArrayRegion(env, result, 0, (jsize)slice.len, (const jbyte *)slice.data);
		if((*env)->ExceptionCheck(env))
		{
			return NULL;
		}
	}
	return result;
}
jbyteArray jni_consume_buffer(JNIEnv *env, TssBuffer *buffer)
{
	jbyteArray result = jni_buffer_to_byte_array(env, buffer);
	tss_buffer_free(buffer);
	return result;
}
void jni_throw_tss_exception(JNIEnv *env, TssStatus status)
{
	uint8_t error[1024]={0};
	tss_last_error_copy(error, sizeof(error));
	jclass exception_class=(*env)->FindClass(env, "de/cryptearth/crypto/libtss/TssException");
	if(exception_class==NULL)
	{
		return;
	}
	jmethodID constructor=(*env)->GetMethodID(env, exception_class, "<init>", "(ILjava/lang/String;)V");
	if(constructor==NULL)
	{
		return;
	}
	jstring message=(*env)->NewStringUTF(env, (const char *)error);
	if(message==NULL)
	{
		return;
	}
	jobject exception=(*env)->NewObject(env, exception_class, constructor, (jint)status, message);
	if(exception==NULL)
	{
		return;
	}
	(*env)->Throw(env, (jthrowable)exception);
}
