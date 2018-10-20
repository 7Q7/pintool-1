//Groups: @ingroup\s+(API_REF|KNOBS|IMG_BASIC_API|INS_BASIC_API|INS_INST_API|INS_BASIC_API_GEN_IA32|INS_BASIC_API_IA32|INS_MOD_API_GEN_IA32|SEC_BASIC_API|RTN_BASIC_API|REG_BASIC_API|REG_CPU_GENERIC|REG_CPU_IA32|TRACE_BASIC_API|BBL_BASIC_API|SYM_BASIC_API|MISC_PRINT|MISC_PARSE|KNOB_API|KNOB_BASIC|KNOB_PRINT|LOCK|PIN_CONTROL|TRACE_VERSION_API|BUFFER_API|PROTO_API|PIN_PROCESS_API|PIN_THREAD_API|PIN_SYSCALL_API|WINDOWS_SYSCALL_API_UNDOC|DEBUG_API|ERROR_FILE_BASIC|TYPE_BASE|INSTLIB|ALARM|CODECACHE_API|CHILD_PROCESS_API|UTILS|MISC|CONTEXT_API|PHYSICAL_CONTEXT_API|PIN_CALLBACKS|EXCEPTION_API|APPDEBUG_API|STOPPED_THREAD_API|BUFFER_API|PROTO|INST_ARGS|DEPRECATED_PIN_API|INTERNAL_EXCEPTION_PRIVATE_UNDOCUMENTED|PIN_THREAD_PRIVATE|CHILD_PROCESS_INTERNAL|BBL_BASIC|ROGUE_BASIC_API|MESSAGE_TYPE|MESSAGE_BASIC|ERRFILE|MISC_BASIC|ITC_INST_API|CONTEXT_API_UNDOC|EXCEPTION_API_UNDOC|UNDOCUMENTED_PIN_API|OPIN|TRACE_VERSIONS
/* PIN API */

/* THIS FILE IS AUTOMAGICALLY GENERATED - DO NOT CHANGE DIRECTLY*/


extern OS_THREAD_ID PIN_GetTid();

                                                                  /* DO NOT EDIT */
extern THREADID PIN_ThreadId();

                                                                  /* DO NOT EDIT */
extern PIN_THREAD_UID PIN_ThreadUid();

                                                                  /* DO NOT EDIT */
extern OS_THREAD_ID PIN_GetParentTid();

                                                                  /* DO NOT EDIT */
extern VOID PIN_Sleep(UINT32 milliseconds);

                                                                  /* DO NOT EDIT */
extern VOID PIN_Yield();

                                                                  /* DO NOT EDIT */
extern THREADID PIN_SpawnInternalThread(ROOT_THREAD_FUNC * pThreadFunc,
                                           VOID * arg,
                                           size_t stackSize,
                                           PIN_THREAD_UID * pThreadUid);

                                                                  /* DO NOT EDIT */
extern VOID PIN_ExitThread(INT32 exitCode);

                                                                  /* DO NOT EDIT */
extern BOOL PIN_IsApplicationThread();

                                                                  /* DO NOT EDIT */
extern BOOL PIN_WaitForThreadTermination(const PIN_THREAD_UID & threadUid,
                                            UINT32 milliseconds,
                                            INT32 * pExitCode);

                                                                  /* DO NOT EDIT */

