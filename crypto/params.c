/*-
 * Copyright 2009 Colin Percival
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include "php.h"
#ifdef PHP_WIN32
#include "zend_config.w32.h"
#endif

#include "php_globals.h"
#include "php_variables.h"
#include "php_getopt.h"
#include "zend_builtin_functions.h"
#include "zend_extensions.h"
#include "zend_modules.h"
#include "zend_globals.h"
#include "zend_ini_scanner.h"
#include "zend.h"
#include "zend_alloc.h"
#include "php_config.h"
# include "TSRM.h"


#include <errno.h>

#include <stddef.h>

#ifdef PHP_WIN32
# include "win32/time.h"
# include "win32/php_stdint.h"
#else
# include <stdint.h>
# include <unistd.h>
#endif
#include <errno.h>
#include <time.h>
#ifndef PHP_WIN32
# include <sys/time.h>
# include <sys/resource.h>
#endif
#include <sys/types.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_SYSCTL_HW_USERMEM
#include <sys/sysctl.h>
#endif
#ifdef HAVE_SYS_SYSINFO_H
#include <sys/sysinfo.h>
#define HAVE_SYSINFO
#endif

#include "params.h"

#include "crypto/crypto_scrypt.h"
 
static int memtouse(size_t, double, size_t *);
static int scryptenc_cpuperf(double * opps);
 
int
pickparams(size_t maxmem, double maxmemfrac, double maxtime,
    int * logN, uint32_t * r, uint32_t * p)
{
    size_t memlimit;
    double opps;
    double opslimit;
    double maxN, maxrp;
    int rc;

    /* Figure out how much memory to use. */
    if (memtouse(maxmem, maxmemfrac, &memlimit))
        return (1);

    /* Figure out how fast the CPU is. */
    if ((rc = scryptenc_cpuperf(&opps)) != 0)
        return (rc);
    opslimit = opps * maxtime;

    /* Allow a minimum of 2^15 salsa20/8 cores. */
    if (opslimit < 32768)
        opslimit = 32768;

    /* Fix r = 8 for now. */
    *r = 8;

    /*
     * The memory limit requires that 128Nr <= memlimit, while the CPU
     * limit requires that 4Nrp <= opslimit.  If opslimit < memlimit/32,
     * opslimit imposes the stronger limit on N.
     */
#ifdef DEBUG
    fprintf(stderr, "Requiring 128Nr <= %zu, 4Nrp <= %f\n",
        memlimit, opslimit);
#endif
    if (opslimit < memlimit/32) {
        /* Set p = 1 and choose N based on the CPU limit. */
        *p = 1;
        maxN = opslimit / (*r * 4);
        for (*logN = 1; *logN < 63; *logN += 1) {
            if ((uint64_t)(1) << *logN > maxN / 2)
                break;
        }
    } else {
        /* Set N based on the memory limit. */
        maxN = memlimit / (*r * 128);
        for (*logN = 1; *logN < 63; *logN += 1) {
            if ((uint64_t)(1) << *logN > maxN / 2)
                break;
        }

        /* Choose p based on the CPU limit. */
        maxrp = (opslimit / 4) / ((uint64_t)(1) << *logN);
        if (maxrp > 0x3fffffff)
            maxrp = 0x3fffffff;
        *p = (uint32_t)(maxrp) / *r;
    }


    /* Success! */
    return (0);
}

int
checkparams(size_t maxmem, double maxmemfrac, double maxtime,
    int logN, uint32_t r, uint32_t p)
{
    size_t memlimit;
    double opps;
    double opslimit;
    uint64_t N;
    int rc;

    /* Figure out the maximum amount of memory we can use. */
    if (memtouse(maxmem, maxmemfrac, &memlimit))
        return (1);

    /* Figure out how fast the CPU is. */
    if ((rc = scryptenc_cpuperf(&opps)) != 0)
        return (rc);
    opslimit = opps * maxtime;

    /* Sanity-check values. */
    if ((logN < 1) || (logN > 63))
        return (7);
    if ((uint64_t)(r) * (uint64_t)(p) >= 0x40000000)
        return (7);

    /* Check limits. */
    N = (uint64_t)(1) << logN;
    if ((memlimit / N) / r < 128)
        return (9);
    if ((opslimit / N) / (r * p) < 4)
        return (10);

    /* Success! */
    return (0);
}

#ifdef HAVE_CLOCK_GETTIME

static clock_t clocktouse;

static int
getclockres(double * resd)
{
    struct timespec res;

    /*
     * Try clocks in order of preference until we find one which works.
     * (We assume that if clock_getres works, clock_gettime will, too.)
     * The use of if/else/if/else/if/else rather than if/elif/elif/else
     * is ugly but legal, and allows us to #ifdef things appropriately.
     */
#ifdef CLOCK_VIRTUAL
    if (clock_getres(CLOCK_VIRTUAL, &res) == 0)
        clocktouse = CLOCK_VIRTUAL;
    else
#endif
#ifdef CLOCK_MONOTONIC
    if (clock_getres(CLOCK_MONOTONIC, &res) == 0)
        clocktouse = CLOCK_MONOTONIC;
    else
#endif
    if (clock_getres(CLOCK_REALTIME, &res) == 0)
        clocktouse = CLOCK_REALTIME;
    else
        return (-1);

    /* Convert clock resolution to a double. */
    *resd = res.tv_sec + res.tv_nsec * 0.000000001;

    return (0);
}

static int
getclocktime(struct timespec * ts)
{

    if (clock_gettime(clocktouse, ts))
        return (-1);

    return (0);
}

#else
static int
getclockres(double * resd)
{

    *resd = 1.0 / CLOCKS_PER_SEC;

    return (0);
}

static int
getclocktime(struct timespec * ts)
{
    struct timeval tv;

    if (gettimeofday(&tv, NULL))
        return (-1);
    ts->tv_sec = tv.tv_sec;
    ts->tv_nsec = tv.tv_usec * 1000;

    return (0);
}
#endif

static int
getclockdiff(struct timespec * st, double * diffd)
{
    struct timespec en;

    if (getclocktime(&en))
        return (1);
    *diffd = (en.tv_nsec - st->tv_nsec) * 0.000000001 +
        (en.tv_sec - st->tv_sec);

    return (0);
}

/**
 * scryptenc_cpuperf(opps):
 * Estimate the number of salsa20/8 cores which can be executed per second,
 * and return the value via opps.
 */
static int
scryptenc_cpuperf(double * opps)
{
    struct timespec st;
    double resd, diffd;
    uint64_t i = 0;

    /* Get the clock resolution. */
    if (getclockres(&resd))
        return (2);

#ifdef DEBUG
    fprintf(stderr, "Clock resolution is %f\n", resd);
#endif

    /* Loop until the clock ticks. */
    if (getclocktime(&st))
        return (2);
    do {
        /* Do an scrypt. */
        if (crypto_scrypt(NULL, 0, NULL, 0, 16, 1, 1, NULL, 0))
            return (3);

        /* Has the clock ticked? */
        if (getclockdiff(&st, &diffd))
            return (2);
        if (diffd > 0)
            break;
    } while (1);

    /* Could how many scryps we can do before the next tick. */
    if (getclocktime(&st))
        return (2);
    do {
        /* Do an scrypt. */
        if (crypto_scrypt(NULL, 0, NULL, 0, 128, 1, 1, NULL, 0))
            return (3);

        /* We invoked the salsa20/8 core 512 times. */
        i += 512;

        /* Check if we have looped for long enough. */
        if (getclockdiff(&st, &diffd))
            return (2);
        if (diffd > resd)
            break;
    } while (1);

#ifdef DEBUG
    fprintf(stderr, "%ju salsa20/8 cores performed in %f seconds\n",
        (uintmax_t)i, diffd);
#endif

    /* We can do approximately i salsa20/8 cores per diffd seconds. */
    *opps = i / diffd;
    return (0);
}


int
memtouse(size_t maxmem, double maxmemfrac, size_t * memlimit)
{
    size_t memlimit_min;
    size_t memavail;

    /* Memory is constrained by PHP itself */
    memlimit_min = (PG(memory_limit) - (1 TSRMLS_CC))/1024;
    
    	/* Only use the specified fraction of the available memory. */
	if ((maxmemfrac > 0.5) || (maxmemfrac == 0.0))
		maxmemfrac = 0.5;
	memavail = maxmemfrac * memlimit_min;

	/* Don't use more than the specified maximum. */
	if ((maxmem > 0) && (memavail > maxmem))
		memavail = maxmem;

	/* But always allow at least 1 MiB. */
	if (memavail < 1048576/1024)
        {
                memavail = 1048576/1024;
        }
		
  
    /* Return limit via the provided pointer. */
    *memlimit = memavail;
    return (0);
}
