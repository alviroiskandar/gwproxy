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

#include <stdbool.h>

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

/*
 * @c with A-Z lowered to a-z and every other byte left alone. tolower()
 * follows the locale; protocol names and keys must fold the same bytes
 * whatever it is, most of all where a compare and a hash have to agree.
 */
static inline unsigned char gwp_ascii_lower(unsigned char c)
{
	return (c >= 'A' && c <= 'Z') ? (unsigned char)(c | 0x20) : c;
}

/*
 * Parse all of @s as an unsigned number of at most @max into *@out; -1 if it
 * is not one. It is decimal digits, or with @hex also "0x" (or "0X") and
 * hexadecimal digits; nothing else. strtoul() is not used: it also takes
 * leading blanks and a sign, and negates a "-" value in unsigned arithmetic, so
 * "-18446744073709551535" would wrap around to 81, and " 80" and "+80" would
 * pass for 80; with base 0 it reads "010" as octal 8, and a newer C library
 * "0b10" as binary 2. Where @hex allows a prefix, a decimal number may not
 * start with 0, so "010", which meant 8 before, is refused rather than quietly
 * read as 10; without @hex it is plain decimal and "010" is 10, as it always
 * was.
 */
static inline int gwp_parse_unum(const char *s, bool hex,
				 unsigned long long max,
				 unsigned long long *out)
{
	unsigned long long v = 0, base = 10;
	int d;

	if (*s < '0' || *s > '9')
		return -1;
	if (hex && s[0] == '0' && s[1]) {
		if (s[1] != 'x' && s[1] != 'X')
			return -1;
		base = 16;
		s += 2;
		if (!*s)
			return -1;
	}
	for (; *s; s++) {
		d = gwp_hex_val((unsigned char)*s);
		if (d < 0 || (unsigned long long)d >= base)
			return -1;
		if ((unsigned long long)d > max ||
		    v > (max - (unsigned long long)d) / base)
			return -1;
		v = v * base + (unsigned long long)d;
	}
	*out = v;
	return 0;
}

#endif /* #ifndef GWPROXY__ASCII_H */
