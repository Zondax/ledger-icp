/*******************************************************************************
*   (c) 2018 - 2023 Zondax AG
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
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#if defined(TARGET_STAX)
    #define JOIN_COMMUNITY_FUND "Join Community Fund"
    #define INCREASE_DISSOLVE_DELAY "Increase Dissolve\nDelay"
    #define START_DISSOLVE_NEURON "Start Dissolve Neuron"
    #define STOP_DISSOLVE_NEURON "Stop Dissolve Neuron"
#else
    #define JOIN_COMMUNITY_FUND "Join Community     Fund"
    #define INCREASE_DISSOLVE_DELAY "Increase Dissolve  Delay"
    #define START_DISSOLVE_NEURON "Start Dissolve     Neuron"
    #define STOP_DISSOLVE_NEURON "Stop Dissolve      Neuron"
#endif



#ifdef __cplusplus
}
#endif
