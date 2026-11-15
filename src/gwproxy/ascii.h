// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 *
 * ASCII text helpers that follow no locale: the bytes of a protocol or a
 * configuration file mean the same whatever locale the proxy runs in. This
 * header includes nothing but what it needs, so that modules built alone in
 * their unit tests, and headers included before the system ones, can use it.
 */
#ifndef GWPROXY__ASCII_H
#define GWPROXY__ASCII_H

/* The value of hexadecimal digit @c (0-9, a-f, A-F), or -1 if it is not one. */
static inline int gwp_hex_val(unsigned char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	c |= 0x20;
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1;
}

#endif /* #ifndef GWPROXY__ASCII_H */
