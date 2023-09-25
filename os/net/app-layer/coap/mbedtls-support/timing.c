/*
 *  Portable interface to the CPU cycle counter
 *  Contiki-NG port
 *
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

#include "common.h"

#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf     printf
#endif

#include "mbedtls/timing.h"

//TODO Joel, this is weird
// Included for Porting to Contiki-NG
// Contiki-NG timer module
#include "contiki.h"



#ifndef asm
#define asm __asm
#endif

#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <signal.h>
#include <time.h>
#include <stdio.h>


#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&  \
    ( defined(_MSC_VER) && defined(_M_IX86) ) || defined(__WATCOMC__)

#define HAVE_HARDCLOCK

unsigned long mbedtls_timing_hardclock( void )
{
    unsigned long tsc;
    __asm   rdtsc
    __asm   mov  [tsc], eax
    return( tsc );
}
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          ( _MSC_VER && _M_IX86 ) || __WATCOMC__ */

/* some versions of mingw-64 have 32-bit longs even on x84_64 */
#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&  \
    defined(__GNUC__) && ( defined(__i386__) || (                       \
    ( defined(__amd64__) || defined( __x86_64__) ) && __SIZEOF_LONG__ == 4 ) )

#define HAVE_HARDCLOCK

unsigned long mbedtls_timing_hardclock( void )
{
    unsigned long lo, hi;
    asm volatile( "rdtsc" : "=a" (lo), "=d" (hi) );
    return( lo );
}
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          __GNUC__ && __i386__ */

#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&  \
    defined(__GNUC__) && ( defined(__amd64__) || defined(__x86_64__) )

#define HAVE_HARDCLOCK

unsigned long mbedtls_timing_hardclock( void )
{
    unsigned long lo, hi;
    asm volatile( "rdtsc" : "=a" (lo), "=d" (hi) );
    return( lo | ( hi << 32 ) );
}
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          __GNUC__ && ( __amd64__ || __x86_64__ ) */

#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&  \
    defined(__GNUC__) && ( defined(__powerpc__) || defined(__ppc__) )

#define HAVE_HARDCLOCK

unsigned long mbedtls_timing_hardclock( void )
{
    unsigned long tbl, tbu0, tbu1;

    do
    {
        asm volatile( "mftbu %0" : "=r" (tbu0) );
        asm volatile( "mftb  %0" : "=r" (tbl ) );
        asm volatile( "mftbu %0" : "=r" (tbu1) );
    }
    while( tbu0 != tbu1 );

    return( tbl );
}
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          __GNUC__ && ( __powerpc__ || __ppc__ ) */

#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&  \
    defined(__GNUC__) && defined(__sparc64__)

#if defined(__OpenBSD__)
#warning OpenBSD does not allow access to tick register using software version instead
#else
#define HAVE_HARDCLOCK

unsigned long mbedtls_timing_hardclock( void )
{
    unsigned long tick;
    asm volatile( "rdpr %%tick, %0;" : "=&r" (tick) );
    return( tick );
}
#endif /* __OpenBSD__ */
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          __GNUC__ && __sparc64__ */

#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&  \
    defined(__GNUC__) && defined(__sparc__) && !defined(__sparc64__)

#define HAVE_HARDCLOCK

unsigned long mbedtls_timing_hardclock( void )
{
    unsigned long tick;
    asm volatile( ".byte 0x83, 0x41, 0x00, 0x00" );
    asm volatile( "mov   %%g1, %0" : "=r" (tick) );
    return( tick );
}
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          __GNUC__ && __sparc__ && !__sparc64__ */

#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&      \
    defined(__GNUC__) && defined(__alpha__)

#define HAVE_HARDCLOCK

unsigned long mbedtls_timing_hardclock( void )
{
    unsigned long cc;
    asm volatile( "rpcc %0" : "=r" (cc) );
    return( cc & 0xFFFFFFFF );
}
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          __GNUC__ && __alpha__ */

#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&      \
    defined(__GNUC__) && defined(__ia64__)

#define HAVE_HARDCLOCK

unsigned long mbedtls_timing_hardclock( void )
{
    unsigned long itc;
    asm volatile( "mov %0 = ar.itc" : "=r" (itc) );
    return( itc );
}
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          __GNUC__ && __ia64__ */




/* ASK IF HARD LOCK IS NEEDED */

#if !defined(HAVE_HARDCLOCK)

#define HAVE_HARDCLOCK

static int hardclock_init = 0;
static struct timer tv_init;
/* might not work */
unsigned long mbedtls_timing_hardclock( void )
{
    clock_time_t tv_cur;
    timer_set(&tv_init, 0);

    if( hardclock_init == 0 )
    {
        timer_reset(&tv_init);
        hardclock_init = 1;
    }

    tv_cur = clock_time();
    /* in miliseconds */
    uint64_t delta;
    delta = ( ((tv_cur - tv_init.start) * 1000) / CLOCK_SECOND ) ;
    return delta;
}
#endif /* !HAVE_HARDCLOCK */

volatile int mbedtls_timing_alarmed = 0;

/*
 * Get elapsed time in milliseconds or reset timer
 */
//TODO
uint64_t mbedtls_timing_get_timer_internal( struct timer *t, int reset )
{

    if( reset )
    {
        timer_reset(t);
        return( 0 );
    }
    else
    {
        uint64_t delta;
        clock_time_t now;
        now = clock_time();
	/* in milliseconds */
        delta = ((now - t->start) * 1000) / CLOCK_SECOND;
        return( delta );
    }
}

static void sighandler( int signum )
{
    mbedtls_timing_alarmed = 1;
    signal( signum, sighandler );
}

void mbedtls_set_alarm( int seconds )
{
    mbedtls_timing_alarmed = 0;
    signal( SIGALRM, sighandler );
    alarm( seconds );
    if( seconds == 0 )
    {
        /* alarm(0) cancelled any previous pending alarm, but the
           handler won't fire, so raise the flag straight away. */
        mbedtls_timing_alarmed = 1;
    }
}

/*
 * Set delays to watch
 */
void mbedtls_timing_set_delay( void *data, uint32_t int_ms, uint32_t fin_ms )
{
    mbedtls_timing_delay_context *ctx = (mbedtls_timing_delay_context *) data;

    ctx->int_ms = int_ms;
    ctx->fin_ms = fin_ms;
    /* convert ms to ticks */
    uint64_t interval = (fin_ms * CLOCK_SECOND) / 1000;

    /* initialize timer */
    timer_set(&ctx->timer, interval);

    /* reset timer */
    if( fin_ms != 0 )
        (void) mbedtls_timing_get_timer_internal( &ctx->timer, 1 );
}

/*
 * Get number of delays expired
 */
int mbedtls_timing_get_delay( void *data )
{
    mbedtls_timing_delay_context *ctx = (mbedtls_timing_delay_context *) data;
    uint64_t elapsed_ms;

    if( ctx->fin_ms == 0 )
        return( -1 );

    elapsed_ms = mbedtls_timing_get_timer_internal( &ctx->timer, 0 );

    if( elapsed_ms >= ctx->fin_ms )
        return( 2 );

    if( elapsed_ms >= ctx->int_ms )
        return( 1 );

    return( 0 );
}

