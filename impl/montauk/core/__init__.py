# SPDX-License-Identifier: Apache-2.0
"""Sans-IO protocol core: no sockets, no clocks, no randomness in the hot path.

Every module takes bytes and explicit time values in and returns bytes and
values out. I/O lives in the daemon/client layers (M1+).
"""
