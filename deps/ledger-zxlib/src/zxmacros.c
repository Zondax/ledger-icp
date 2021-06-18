/*******************************************************************************
*   (c) 2018 Zondax GmbH
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
#include "zxmacros.h"

void handle_stack_overflow() {
    zemu_log("!!!!!!!!!!!!!!!!!!!!!! CANARY TRIGGERED!!! STACK OVERFLOW DETECTED\n");
#if defined (TARGET_NANOS) || defined(TARGET_NANOX)
    io_seproxyhal_se_reset();
#else
    while (1);
#endif
}

void check_app_canary() {
#if defined (TARGET_NANOS) || defined(TARGET_NANOX)
    if (app_stack_canary != APP_STACK_CANARY_MAGIC) handle_stack_overflow();
#endif
}

void zemu_log_stack(const char *ctx) {
#if defined(ZEMU_LOGGING) && (defined (TARGET_NANOS) || defined(TARGET_NANOX))
#define STACK_SHIFT 20
    void* p = NULL;
    char buf[70];
    snprintf(buf, sizeof(buf), "|SP| %p %p (%d) : %s\n",
            &app_stack_canary,
            ((void*)&p)+STACK_SHIFT,
            (uint32_t)((void*)&p)+STACK_SHIFT - (uint32_t)&app_stack_canary,
            ctx);
    zemu_log(buf);
#else
    (void)ctx;
#endif
}
