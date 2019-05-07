#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.
#

# Script for testing correctness of CTAP2/CTAP1 security token

import sys

from solo.fido2 import force_udp_backend
from tests import Tester, FIDO2Tests, U2FTests, HIDTests, SoloTests
from tests.pcsc import PCSCDevice, SCGetReader, SCRelease


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: %s [sim]|[pcsc] <[u2f]|[fido2]|[rk]|[hid]|[ping]>")
        sys.exit(0)

    t = Tester()
    t.set_user_count(3)

    if "sim" in sys.argv:
        print("Using UDP backend.")
        force_udp_backend()
        t.set_sim(True)
        t.set_user_count(10)

    if "pcsc" in sys.argv:
        print("Using PCSC backend.")

        handle, reader = SCGetReader();
        if reader != "":
            t.setPCSCDevice(PCSCDevice(handle, reader))
            t.set_user_count(10)
        else:
            print("ERROR: reader not found.")

    t.find_device()

    try:
        if "solo" in sys.argv:
            SoloTests(t).run()

        if "u2f" in sys.argv:
            U2FTests(t).run()

        if "fido2" in sys.argv:
            # t.test_fido2()
            FIDO2Tests(t).run()

        # hid tests are a bit invasive and should be done last
        if "hid" in sys.argv:
            HIDTests(t).run()

        if "bootloader" in sys.argv:
            if t.is_sim:
                raise RuntimeError("Cannot test bootloader in simulation yet.")
            # print("Put device in bootloader mode and then hit enter")
            # input()
            # t.test_bootloader()

        # t.test_responses()
        # t.test_fido2_brute_force()
    finally:
        if 'handle' in vars():
            SCRelease(handle)
