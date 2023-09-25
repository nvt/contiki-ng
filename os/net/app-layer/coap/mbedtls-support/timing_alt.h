/**
 * \file timing.h
 *
 * \brief Portable interface to timeouts and to the CPU cycle counter Contiki-NG ported
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
#ifndef MBEDTLS_ALT_TIMING_H
#define MBEDTLS_ALT_TIMING_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stdint.h>
/*<ADDED_FOR_PORT>*/
#include "contiki.h"
/*<END>*/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          internal timer structure
 */
struct mbedtls_timing_hr_time {
    uint64_t opaque[4];
};


/**
 * \brief          Context for mbedtls_timing_set/get_delay().
 *                 POSIX structure replaced with Contiki_NG timer.
 *                 Intermediate and final delay not changed.
 */
typedef struct mbedtls_timing_delay_context
{
    struct timer timer;           /*Contiki timer sturcture*/
    uint32_t     int_ms;
    uint32_t     fin_ms;
} mbedtls_timing_delay_context;


extern volatile int mbedtls_timing_alarmed;

/**
 * \brief          Return the CPU cycle counter value
 *
 * \warning        This is only a best effort! Do not rely on this!
 *                 In particular, it is known to be unreliable on virtual
 *                 machines.
 *
 * \note           This value starts at an unspecified origin and
 *                 may wrap around.
 */
unsigned long mbedtls_timing_hardclock( void );

/**
 * \brief          Return the elapsed time in milliseconds
 *
 * \param val      points to a timer structure
 * \param reset    If 0, query the elapsed time. Otherwise (re)start the timer.
 *
 * \return         Elapsed time since the previous reset in ms. When
 *                 restarting, this is always 0.
 *
 * \note           To initialize a timer, call this function with reset=1.
 *
 *                 Determining the elapsed time and resetting the timer is not
 *                 atomic on all platforms, so after the sequence
 *                 `{ get_timer(1); ...; time1 = get_timer(1); ...; time2 =
 *                 get_timer(0) }` the value time1+time2 is only approximately
 *                 the delay since the first reset.
 *                 
 *                 Contiki-NG timers work with clock cycles, thus after timer subtraction
 *                 the clock cycles are converted to milliseconds.
 */
uint64_t mbedtls_timing_get_timer_internal( struct timer *val, int reset ); //TODO

/**
 * \brief          Setup an alarm clock
 *
 * \param seconds  delay before the "mbedtls_timing_alarmed" flag is set
 *                 (must be >=0)
 *
 * \warning        Only one alarm at a time  is supported. In a threaded
 *                 context, this means one for the whole process, not one per
 *                 thread.
 */
void mbedtls_set_alarm( int seconds );

/**
 * \brief          Set a pair of delays to watch
 *                 (See \c mbedtls_timing_get_delay().)
 *
 * \param data     Pointer to timing data.
 *                 Must point to a valid \c mbedtls_timing_delay_context struct.
 * \param int_ms   First (intermediate) delay in milliseconds.
 *                 The effect if int_ms > fin_ms is unspecified.
 * \param fin_ms   Second (final) delay in milliseconds.
 *                 Pass 0 to cancel the current delay.
 *
 * \note           The intermediate delay (int_ms) is currently not used.
 *                 The final delay (fin_ms) is converted to clock cycles and passed
 *                 to the timer in the given strucutre and \c mbedtls_timing_get_delay()
 *                 is called to reset/start the timer.
 */
void mbedtls_timing_set_delay( void *data, uint32_t int_ms, uint32_t fin_ms );

/**
 * \brief          Get the status of delays
 *                 (Memory helper: number of delays passed.)
 *
 * \param data     Pointer to timing data
 *                 Must point to a valid \c mbedtls_timing_delay_context struct.
 *
 * \return         -1 if cancelled (fin_ms = 0),
 *                  0 if none of the delays are passed,
 *                  1 if only the intermediate delay is passed,
 *                  2 if the final delay is passed.
 *
 * \note           The data type of elapsed_ms was changed to uint64_t from unsigned
 *                 long as some Contiki-NG platforms might have different type definitions.
 */
int mbedtls_timing_get_delay( void *data );


#ifdef __cplusplus
}
#endif

#endif /* timing.h */
