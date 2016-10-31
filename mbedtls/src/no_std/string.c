/*
 * Various standard string routines in C.
 * 
 * Written in 2016 by Jethro G. Beekman
 * 
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.
 * 
 * You should have received a copy of the CC0 Public Domain Dedication along
 * with this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#define __NO_STRING_INLINES
#include <string.h>

size_t strlen(const char *s) {
	const char* cur;
	for (cur=s;*cur;cur++);
	return cur-s;
}

char *strncpy(char *dst, const char *src, size_t n) {
	size_t cur;
	for (cur=0;cur<n&&src[cur];cur++)
		dst[cur]=src[cur];
	if (cur<n)
		dst[cur]=0;
	return dst;
}

int strncmp(const char *s1, const char *s2, size_t n) {
	const char* s1e;
	for (s1e=s1+n;s1!=s1e&&*s1&&*s2;s1++,s2++) {
		if (*s1<*s2) {
			return -1;
		} else if (*s1>*s2) {
			return 1;
		}
	}
	return 0;
}

int strcmp(const char *s1, const char *s2) {
	for (;*s1&&*s2;s1++,s2++) {
		if (*s1<*s2) {
			return -1;
		} else if (*s1>*s2) {
			return 1;
		}
	}
	return 0;
}
