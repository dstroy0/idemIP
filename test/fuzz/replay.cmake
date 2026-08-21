# idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Hand every seed in the corpus to the replay binary, in one call. The glob is done here rather
# than at configure time because the corpus is written by the build: a seed added to
# seed_corpus.py is replayed by the next `ctest` without re-configuring, and a corpus that came out
# empty is a failure and not a pass over nothing.

file(GLOB IDEMIP_SEEDS "${IDEMIP_CORPUS}/*.bin")
list(LENGTH IDEMIP_SEEDS IDEMIP_SEED_COUNT)
if(IDEMIP_SEED_COUNT EQUAL 0)
    message(FATAL_ERROR "fuzz_corpus: no seed in ${IDEMIP_CORPUS} - seed_corpus.py wrote nothing")
endif()

execute_process(COMMAND "${IDEMIP_REPLAY}" ${IDEMIP_SEEDS} RESULT_VARIABLE IDEMIP_RC)
if(NOT IDEMIP_RC EQUAL 0)
    message(FATAL_ERROR "fuzz_corpus: the replay of ${IDEMIP_SEED_COUNT} seeds reported ${IDEMIP_RC}")
endif()
