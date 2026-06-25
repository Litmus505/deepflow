#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jni.h>
#include <jvmti.h>

#define STRING_BUFFER_SIZE 2048

typedef enum {
    METHOD_LOAD,
    METHOD_UNLOAD,
    DYNAMIC_CODE_GEN
} event_type;

typedef struct {
    unsigned short len;
    unsigned short type;
} symbol_metadata;

static jvmtiEnv* jvmti = NULL;

static void JNICALL callbackCompiledMethodLoad(jvmtiEnv *jvmti,
                                                jmethodID method,
                                                jint code_size,
                                                const void *code_addr,
                                                jint map_length,
                                                const jvmtiAddrLocationMap *map,
                                                const void *compile_info) {
    jclass klass;
    char *class_name = NULL;
    char *method_name = NULL;
    char *method_sig = NULL;

    if ((*jvmti)->GetMethodName(jvmti, method, &method_name, &method_sig, NULL) == JVMTI_ERROR_NONE &&
        (*jvmti)->GetMethodDeclaringClass(jvmti, method, &klass) == JVMTI_ERROR_NONE &&
        (*jvmti)->GetClassSignature(jvmti, klass, &class_name, NULL) == JVMTI_ERROR_NONE) {
        
        char output[STRING_BUFFER_SIZE];
        snprintf(output, sizeof(output), "%s::%s%s", class_name, method_name, method_sig);
        printf("[Symbol Load] %lx %x %s\n", (unsigned long)code_addr, code_size, output);
        
        if (class_name) (*jvmti)->Deallocate(jvmti, (unsigned char *)class_name);
    }
    
    if (method_name) (*jvmti)->Deallocate(jvmti, (unsigned char *)method_name);
    if (method_sig) (*jvmti)->Deallocate(jvmti, (unsigned char *)method_sig);
}

static void JNICALL callbackDynamicCodeGenerated(jvmtiEnv *jvmti,
                                                  const char *name,
                                                  const void *address,
                                                  jint length) {
    printf("[Dynamic Code] %lx %x %s\n", (unsigned long)address, length, name);
}

static void JNICALL callbackCompiledMethodUnload(jvmtiEnv *jvmti,
                                                  jmethodID method,
                                                  const void *address) {
    printf("[Symbol Unload] %lx\n", (unsigned long)address);
}

JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved) {
    printf("Simple JVMTI Agent Loading...\n");
    
    jint result = (*vm)->GetEnv(vm, (void **)&jvmti, JVMTI_VERSION_1_0);
    if (result != JNI_OK || jvmti == NULL) {
        fprintf(stderr, "Failed to get JVMTI environment\n");
        return JNI_ERR;
    }
    
    jvmtiCapabilities capabilities;
    memset(&capabilities, 0, sizeof(capabilities));
    capabilities.can_generate_compiled_method_load_events = 1;
    
    if ((*jvmti)->AddCapabilities(jvmti, &capabilities) != JVMTI_ERROR_NONE) {
        fprintf(stderr, "Failed to add capabilities\n");
        return JNI_ERR;
    }
    
    jvmtiEventCallbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.CompiledMethodLoad = &callbackCompiledMethodLoad;
    callbacks.CompiledMethodUnload = &callbackCompiledMethodUnload;
    callbacks.DynamicCodeGenerated = &callbackDynamicCodeGenerated;
    
    if ((*jvmti)->SetEventCallbacks(jvmti, &callbacks, sizeof(callbacks)) != JVMTI_ERROR_NONE) {
        fprintf(stderr, "Failed to set callbacks\n");
        return JNI_ERR;
    }
    
    if ((*jvmti)->SetEventNotificationMode(jvmti, JVMTI_ENABLE, JVMTI_EVENT_COMPILED_METHOD_LOAD, NULL) != JVMTI_ERROR_NONE ||
        (*jvmti)->SetEventNotificationMode(jvmti, JVMTI_ENABLE, JVMTI_EVENT_COMPILED_METHOD_UNLOAD, NULL) != JVMTI_ERROR_NONE ||
        (*jvmti)->SetEventNotificationMode(jvmti, JVMTI_ENABLE, JVMTI_EVENT_DYNAMIC_CODE_GENERATED, NULL) != JVMTI_ERROR_NONE) {
        fprintf(stderr, "Failed to enable notifications\n");
        return JNI_ERR;
    }
    
    printf("Simple JVMTI Agent Loaded Successfully!\n");
    return JNI_OK;
}

JNIEXPORT void JNICALL Agent_OnUnload(JavaVM *vm) {
    printf("Simple JVMTI Agent Unloading...\n");
}
