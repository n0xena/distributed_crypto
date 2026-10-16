#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include "de_cryptearth_crypto_libtss_LibTss.h"
#include "libtss_jni.h"
#include "libtss.h"
JNIEXPORT void JNICALL Java_de_cryptearth_crypto_libtss_LibTss_init0(JNIEnv *env, jclass clazz, jint flags)
{
	(void)clazz;
	if(flags<0)
	{
		jclass exception_class=(*env)->FindClass(env, "java/lang/IllegalArgumentException");
		if(exception_class!=NULL)
		{
			(*env)->ThrowNew(env, exception_class, "flags must not be negative");
		}
		return;
	}
	TssStatus status=tss_init((uint32_t)flags);
	if(status!=TSS_OK)
	{
		jni_throw_tss_exception(env, status);
	}
}
JNIEXPORT void JNICALL Java_de_cryptearth_crypto_libtss_LibTss_handleFree0(JNIEnv *env, jclass clazz, jlong handle)
{
	(void)env;
	(void)clazz;
	if(handle!=0)
	{
		tss_handle_free((TssHandle)handle);
	}
}
JNIEXPORT void JNICALL Java_de_cryptearth_crypto_libtss_LibTss_sessionFree0(JNIEnv *env, jclass clazz, jlong session)
{
	(void)env;
	(void)clazz;
	if(session!=0)
	{
		tss_session_free((TssHandle)session);
	}
}
