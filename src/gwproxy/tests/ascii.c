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

int main(void)
{
	test_hex_val();
	printf("ascii: %u checks passed\n", nr_checks);
	return 0;
}
