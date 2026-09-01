// SPDX-License-Identifier: GPL-2.0-only

#include <test_progs.h>

#include "verifier_noreturn_kfunc.skel.h"

void test_verifier_noreturn_kfunc(void)
{
	RUN_TESTS(verifier_noreturn_kfunc);
}
