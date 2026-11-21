// idemIP v0.2.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// The capabilities header of a build that gives no compile definition. Only the capability check in
// test/CMakeLists.txt has this directory on its include path. Two values differ from the defaults. The
// check thus sees that idemip_config.h read them from here.

#ifndef IDEMIP_TEST_CAPABILITIES_H
#define IDEMIP_TEST_CAPABILITIES_H

#define IDEMIP_ENABLE_ETHERNET 1
#define IDEMIP_ENABLE_IPV4 1
#define IDEMIP_ENABLE_IPV6 0
#define IDEMIP_ENABLE_TCP 1
#define IDEMIP_ENABLE_UDP 0
#define IDEMIP_ENABLE_TIME_DETERMINISM 0
#define IDEMIP_TIME_DETERMINISM_GRADE 2

#endif // IDEMIP_TEST_CAPABILITIES_H
