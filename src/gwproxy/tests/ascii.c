// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 *
 * Unit tests for the locale-free ASCII helpers (ascii.h). Each is checked
 * against an independent definition for every byte value, so a change to
 * one of them cannot quietly change what a parser accepts.
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <gwproxy/ascii.h>

static unsigned nr_checks;

static void test_hex_val(void)
{
	static const char lower[] = "0123456789abcdef";
	static const char upper[] = "0123456789ABCDEF";
	unsigned c;
	int i, want;

	for (c = 0; c < 256; c++) {
		want = -1;
		for (i = 0; i < 16; i++) {
			if (c == (unsigned char)lower[i] ||
			    c == (unsigned char)upper[i])
				want = i;
		}
		assert(gwp_hex_val((unsigned char)c) == want);
		nr_checks++;
	}
}

static void check_unum(const char *s, bool hex, unsigned long long max,
		       int want_r, unsigned long long want, int line)
{
	unsigned long long v = 0xdeadbeefull;
	int r = gwp_parse_unum(s, hex, max, &v);

	if (r != want_r || (!r && v != want) || (r && v != 0xdeadbeefull)) {
		fprintf(stderr, "line %d: \"%s\" hex=%d max=%llu: got %d %llu\n",
			line, s, hex, max, r, v);
		assert(0);
	}
	nr_checks++;
}

/* Parses to @want. */
#define NUM(s, hex, max, want)	check_unum((s), (hex), (max), 0, (want), \
					   __LINE__)
/* Refused; *out is left alone. */
#define BAD(s, hex, max)	check_unum((s), (hex), (max), -1, 0, __LINE__)

static void test_parse_unum(void)
{
	const unsigned long long u64 = 18446744073709551615ull;

	NUM("0", false, 0, 0);
	NUM("0", true, 0, 0);
	NUM("80", false, 65535, 80);
	NUM("65535", false, 65535, 65535);
	BAD("65536", false, 65535);
	/* Without @hex, a leading 0 is just decimal. */
	NUM("010", false, 100, 10);
	NUM("00", false, 0, 0);
	BAD("0x10", false, 100);
	/* With @hex, a leading 0 must start "0x". */
	BAD("010", true, 100);
	BAD("00", true, 100);
	NUM("0x10", true, 100, 16);
	NUM("0X1f", true, 100, 31);
	NUM("0xABCDEF", true, u64, 0xabcdef);
	NUM("0x0", true, 0, 0);
	NUM("10", true, 100, 10);
	BAD("0x", true, 100);
	BAD("0x-1", true, 100);
	BAD("0xg", true, 100);
	/* Hex letters only after "0x". */
	BAD("1f", true, 100);
	BAD("1a", false, 100);
	/* No sign, blank or other junk anywhere. */
	BAD("", false, 100);
	BAD("", true, 100);
	BAD("-1", false, 100);
	BAD("+1", false, 100);
	BAD(" 1", false, 100);
	BAD("1 ", false, 100);
	BAD("5s", false, 100);
	BAD("x10", true, 100);
	BAD("0b10", true, 100);
	BAD("-18446744073709551535", false, u64);
	/* The limit, and one past it, in both bases. */
	NUM("18446744073709551615", false, u64, u64);
	BAD("18446744073709551616", false, u64);
	BAD("99999999999999999999", false, u64);
	NUM("0xffffffffffffffff", true, u64, u64);
	BAD("0x10000000000000000", true, u64);
	NUM("4294967295", false, 4294967295ull, 4294967295ull);
	BAD("4294967296", false, 4294967295ull);
	NUM("0xffffffff", true, 4294967295ull, 4294967295ull);
	BAD("0x100000000", true, 4294967295ull);
	/* A digit above a small @max on its own. */
	BAD("7", false, 5);
	NUM("5", false, 5, 5);
	BAD("0x6", true, 5);
}

int main(void)
{
	test_hex_val();
	test_parse_unum();
	printf("ascii: %u checks passed\n", nr_checks);
	return 0;
}
