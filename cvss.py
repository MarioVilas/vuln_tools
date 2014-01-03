#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2014, Mario Vilas
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice,this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

__all__ = ["CVSS_Base"]

class CVSS_Base(object):

    METRICS = (
        "AV", "AC", "Au",
        "C", "I", "A",
    )

    ADJACENT_NETWORK = "A"
    COMPLETE = "C"
    HIGH = "H"
    LOCAL = "L"
    LOW = "L"
    MEDIUM = "M"
    NETWORK = "N"
    NONE = "N"
    MULTIPLE = "M"
    PARTIAL = "P"
    SINGLE = "S"

    AV_SCORE = {
        LOCAL: 0.395,
        ADJACENT_NETWORK: 0.646,
        NETWORK: 1.0,
    }

    AC_SCORE = {
        HIGH: 0.35,
        MEDIUM: 0.61,
        LOW: 0.71,
    }

    Au_SCORE = {
        MULTIPLE: 0.45,
        SINGLE: 0.56,
        NONE: 0.704,
    }

    C_SCORE = {
        NONE: 0.0,
        PARTIAL: 0.275,
        COMPLETE: 0.66,
    }
    I_SCORE = C_SCORE
    A_SCORE = C_SCORE

    def get_metric(self, metric):
        return getattr(self, "_CVSS_Base__" + metric)

    def set_metric(self, metric, value):
        try:
            scores = getattr(self, metric + "_SCORE")
        except AttributeError:
            raise ValueError("Invalid metric: %r" % (metric,))
        try:
            score = scores[value]
        except KeyError:
            if value in scores.values():
                score = value
            else:
                raise ValueError("Invalid %s value: %r" % (metric, value))
        setattr(self, "_CVSS_Base__" + metric, score)

    @property
    def exploitability(self):
        return 20.0 * self.AV * self.AC * self.Au

    @property
    def impact(self):
        return 10.41 * (1.0-(1.0-self.C) * (1.0-self.I) * (1.0-self.A))

    @property
    def f_impact(self):
        return 0.0 if self.impact == 0.0 else 1.176

    @property
    def score(self):
        return "%.1f" % (
            self.f_impact * (
                (0.6 * self.impact) + (0.4 * self.exploitability) - 1.5
            )
        )

    @property
    def vector(self):
        vector = []
        for metric in self.METRICS:
            value = getattr(self, metric)
            scores = getattr(self, metric + "_SCORE")
            found = False
            for name, candidate in scores.iteritems():
                if value == candidate:
                    vector.append("%s:%s" % (metric, name))
                    found = True
                    break
            assert found, "Internal error while calculating CVSS base vector"
        return "/".join(vector)

    @vector.setter
    def vector(self, vector):
        try:
            for metric_and_value in vector.split("/"):
                metric, value = metric_and_value.split(":", 1)
                self.set_metric(metric.strip(), value.strip())
        except Exception:
            raise ValueError("Invalid CVSS base vector: %r" % (vector,))

    def __init__(self, vector = "AV:L/AC:L/Au:N/C:N/I:N/A:N"):
        self.vector = vector

    def __str__(self):
        return "%s (%s)" % (self.score, self.vector)

    def __repr__(self):
        return "<%s score=%s vector=%s>" % \
               (self.__class__.__name__, self.score, self.vector)

for _m in CVSS_Base.METRICS:
    def _p(metric):
        def _g(self):
            return self.get_metric(metric)
        def _s(self, value):
            self.set_metric(metric, value)
        return property(_g, _s)
    setattr(CVSS_Base, _m, _p(_m))

CVSS_Base.access_vector = CVSS_Base.AV
CVSS_Base.access_complexity = CVSS_Base.AC
CVSS_Base.authentication = CVSS_Base.Au
CVSS_Base.confidentiality = CVSS_Base.C
CVSS_Base.integrity = CVSS_Base.I
CVSS_Base.availability = CVSS_Base.A

if __name__ == "__main__":
    import sys
    for vector in sys.argv[1:]:
        cvss = CVSS_Base(vector)
        print(cvss)
