#ifndef LIBTSS_JNI_H
#define LIBTSS_JNI_H
#include <stdbool.h>
#include <stddef.h>
#include <jni.h>
#include "libtss.h"
void jni_throw_tss_exception(JNIEnv *env, TssStatus status);
bool jni_get_byte_array(JNIEnv *env, jbyteArray array, jbyte **data, size_t *len);
void jni_release_byte_array(JNIEnv *env, jbyteArray array, jbyte *data);
jbyteArray jni_buffer_to_byte_array(JNIEnv *env, const TssBuffer *buffer);
jbyteArray jni_slice_to_byte_array(JNIEnv *env, TssSlice slice);
jbyteArray jni_consume_buffer(JNIEnv *env, TssBuffer *buffer);
#endif
