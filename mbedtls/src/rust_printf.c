/*
 * Rust interface for mbedTLS
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#include <stdio.h>
#include <stdarg.h>

extern void mbedtls_log(const char* msg);

extern int mbedtls_printf(const char *fmt, ...) {
	va_list ap;

	va_start(ap,fmt);
	int n=vsnprintf(0,0,fmt,ap);
	va_end(ap);

	if (n<0)
	   return -1;

	n++;
	char p[n];

	va_start(ap,fmt);
	n=vsnprintf(p,n,fmt,ap);
	va_end(ap);

	if (n<0)
	   return -1;

	mbedtls_log(p);
	
	return n;
}
