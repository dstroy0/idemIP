// idemIP v0.2.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// The capability check. This file compiles with no IDEMIP_ENABLE_* definition, and with the header beside
// it on its include path. The compile stops where idemip_config.h did not read that header.

#include "src/idemip_config.h"

#if !defined(IDEMIP_ENABLE_ETHERNET) || !defined(IDEMIP_ENABLE_IPV4) || !defined(IDEMIP_ENABLE_IPV6) ||               \
    !defined(IDEMIP_ENABLE_TCP) || !defined(IDEMIP_ENABLE_UDP)
#error "idemip_config.h did not read idemip_capabilities.h"
#endif

_Static_assert(IDEMIP_ENABLE_IPV4 == 1 && IDEMIP_ENABLE_IPV6 == 0, "the IP capabilities are not the ones the header gives");
_Static_assert(IDEMIP_ENABLE_TCP == 1 && IDEMIP_ENABLE_UDP == 0, "the transport capabilities are not the ones the header gives");

// One object. The translation unit is thus not empty.
const unsigned idemip_capabilities_header_timeouts = IDEMIP_TIMEOUTS;
