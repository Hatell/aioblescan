#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# This file deal with EddyStone formated message
#
# Copyright (c) 2018 Harry Karvonen
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies
# or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
# IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE

import aioblescan as aios
from enum import Enum

#
MINEW_UUID=b"\xff\xe1"

def b88_to_float(b88):
  return b88[0] + b88[1]/256.0

class Minew(object):
    """Class defining the content of a Minew advertisement.

    Here the param type will depend on the type.

    """

    def decode(self, packet):
        """Check a parsed packet and figure out if it is an Eddystone Beacon.
        If it is , return the relevant data as a dictionary.

        Return None, it is not an Eddystone Beacon advertising packet"""

        ssu=packet.retrieve("Complete uuids")
        found=False
        for x in ssu:
            if MINEW_UUID in x:
                found=True
                break
        if not found:
            return None

        found=False
        adv=packet.retrieve("Advertised Data")
        for x in adv:
            luuid=x.retrieve("Service Data uuid")
            for uuid in luuid:
                if MINEW_UUID == uuid:
                    found=x
                    break
            if found:
                break

        if not found:
            return None

        try:
            data=found.retrieve("Adv Payload")[0].val
        except:
            return None

        if data[1] == 1:
            return {
                "frameType": data[0],
                "productModel": data[1],
                "batteryPercent": data[2],
                "temperature": b88_to_float(data[3:5]),
                "humidity": b88_to_float(data[5:7]),
                "macAddress": ":".join(["%02x" % x for x in data[12:6:-1]]),
            }
        if data[1] == 8:
            return {
                "frameType": data[0],
                "productModel": data[1],
                "batteryPercent": data[2],
                "macAddress": ":".join(["%02x" % x for x in data[8:2:-1]]),
                "name": data[9:],
            }
        return None
