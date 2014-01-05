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

__all__ = ["CVSS_Base", "CVSS"]

def _p(metric):
    def _g(self):
        return self.get_metric(metric)
    def _s(self, value):
        self.set_metric(metric, value)
    return property(_g, _s)

class cvss_metaclass(type):

    def __init__(cls, name, bases, namespace):
        super(cvss_metaclass, cls).__init__(name, bases, namespace)
        for _m in cls.METRICS:
            setattr(cls, _m, _p(_m))

class CVSS_Base(object):
    "Base CVSS Calculator."

    __metaclass__ = cvss_metaclass

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
    def vector(self):
        vector = []
        for metric in self.METRICS:
            value = self.get_metric(metric)
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
            old_vector = self.vector
        except Exception:
            old_vector = None
        try:
            for metric_and_value in vector.split("/"):
                metric_and_value = metric_and_value.strip()
                if not metric_and_value:
                    continue
                metric, value = metric_and_value.split(":", 1)
                self.set_metric(metric.strip(), value.strip())
            self.vector # sanity check
        except Exception:
            if old_vector is not None:
                self.vector = old_vector
            raise ValueError("Invalid CVSS base vector: %r" % (vector,))

    base_vector = vector

    @property
    def base_exploitability(self):
        return 20.0 * self.AV * self.AC * self.Au

    @property
    def impact(self):
        return 10.41 * (1.0-(1.0-self.C) * (1.0-self.I) * (1.0-self.A))

    @property
    def f_impact(self):
        return 0.0 if self.impact == 0.0 else 1.176

    @property
    def base_score(self):
        return "%.1f" % (
            self.f_impact * (
                (0.6 * self.impact) + (0.4 * self.base_exploitability) - 1.5
            )
        )

    score = base_score

    @property
    def level(self):
        # https://www.pcisecuritystandards.org/pdfs/asv_program_guide_v1.0.pdf
        score = float(self.score)
        if score == 0.0:
            return "INFORMATIONAL"
        if score == 10.0:
            return "CRITICAL"
        if score < 4.0:
            return "LOW"
        if score < 7.0:
            return "MEDIUM"
        return "HIGH"

    def __init__(self, vector = None):
        self.vector = "AV:N/AC:L/Au:N/C:N/I:N/A:N"
        if vector:
            self.vector = vector

    def __str__(self):
        return "%s: %s [%s]" % (self.score, self.level.title(), self.vector)

    def __repr__(self):
        return "<%s score=%s vector=%s>" % \
               (self.__class__.__name__, self.score, self.vector)

CVSS_Base.access_vector = CVSS_Base.AV
CVSS_Base.access_complexity = CVSS_Base.AC
CVSS_Base.authentication = CVSS_Base.Au
CVSS_Base.confidentiality = CVSS_Base.C
CVSS_Base.integrity = CVSS_Base.I
CVSS_Base.availability = CVSS_Base.A

class CVSS(CVSS_Base):
    "CVSS Calculator."

    METRICS = CVSS_Base.METRICS + (
        "E", "RL", "RC",
        "CDP", "TD", "CR", "IR", "AR",
    )

    HIGH = CVSS_Base.HIGH
    LOW = CVSS_Base.LOW
    MEDIUM = CVSS_Base.MEDIUM
    NONE = CVSS_Base.NONE

    CONFIRMED = "C"
    FUNCTIONAL = "F"
    LOW_MEDIUM = "LM"
    MEDIUM_HIGH = "MH"
    NOT_DEFINED = "ND"
    OFFICIAL_FIX = "OF"
    PROOF_OF_CONCEPT = "POC"
    TEMPORARY_FIX = "TF"
    UNAVAILABLE = "U"
    UNCONFIRMED = "UC"
    UNCORROBORATED = "UR"
    UNPROVEN = "U"
    WORKAROUND = "W"

    E_SCORE = {
        UNPROVEN: 0.85,
        PROOF_OF_CONCEPT: 0.9,
        FUNCTIONAL: 0.95,
        HIGH: 1.0,
        NOT_DEFINED: 1.0,
    }

    RL_SCORE = {
        OFFICIAL_FIX: 0.87,
        TEMPORARY_FIX: 0.9,
        WORKAROUND: 0.95,
        UNAVAILABLE: 1.0,
        NOT_DEFINED: 1.0,
    }

    RC_SCORE = {
        UNCONFIRMED: 0.9,
        UNCORROBORATED: 0.95,
        CONFIRMED: 1.0,
        NOT_DEFINED: 1.0,
    }

    CDP_SCORE = {
        NONE: 0.0,
        LOW: 0.1,
        LOW_MEDIUM: 0.3,
        MEDIUM_HIGH: 0.4,
        HIGH: 0.5,
        NOT_DEFINED: 0.0,
    }

    TD_SCORE = {
        NONE: 0.0,
        LOW: 0.25,
        MEDIUM: 0.75,
        HIGH: 1.0,
        NOT_DEFINED: 1.0,
    }

    CR_SCORE = {
        LOW: 0.5,
        MEDIUM: 1.0,
        HIGH: 1.51,
        NOT_DEFINED: 1.0,
    }
    IR_SCORE = CR_SCORE
    AR_SCORE = CR_SCORE

    def __init__(self, vector = None):
        new_metrics = self.METRICS[len(CVSS_Base.METRICS):]
        for metric in new_metrics:
            self.set_metric(metric, self.NOT_DEFINED)
        super(CVSS, self).__init__(vector)

    @property
    def temporal_score(self):
        return "%.1f" % (
            float(self.base_score) * self.E * self.RL * self.RC
        )

    @property
    def adjusted_impact(self):
        return min(10, 10.41 * (
            1 - (1-self.C*self.CR) * (1-self.I*self.IR) * (1-self.A*self.AR)
        ))

    @property
    def adjusted_base_score(self):
        return "%.1f" % (
            self.f_impact * (
                (0.6 * self.adjusted_impact) +
                (0.4 * self.base_exploitability) -
                1.5
            )
        )

    @property
    def adjusted_temporal_score(self):
        return "%.1f" % (
            float(self.adjusted_base_score) * self.E * self.RL * self.RC
        )

    @property
    def environmental_score(self):
        adjusted_temporal = float(self.adjusted_temporal_score)
        return "%.1f" % (
            (adjusted_temporal + (10 - adjusted_temporal) * self.CDP) * self.TD
        )

    score = environmental_score

    @property
    def base_vector(self):
        return "/".join(self.vector.split("/")[:6])

CVSS.exploitability = CVSS.E
CVSS.remediation_level = CVSS.RL
CVSS.report_confidence = CVSS.RC
CVSS.collateral_damage_potential = CVSS.CDP
CVSS.target_distribution = CVSS.TD
CVSS.confidentiality_requirements = CVSS.CR
CVSS.integrity_requirements = CVSS.IR
CVSS.availability_requirements = CVSS.AR

def test():

    # Unit test based on Wikipedia examples.
    cvss = CVSS_Base("AV:N/AC:L/Au:N/C:P/I:P/A:C")
    assert ("%.1f" % cvss.base_exploitability) == "10.0", cvss.base_exploitability
    assert ("%.1f" % cvss.impact) == "8.5", cvss.impact
    assert cvss.base_score == "9.0", cvss.base_score
    assert cvss.score == "9.0", cvss.score
    assert cvss.vector == "AV:N/AC:L/Au:N/C:P/I:P/A:C", cvss.vector
    cvss = CVSS("AV:N/AC:L/Au:N/C:P/I:P/A:C")
    assert ("%.1f" % cvss.base_exploitability) == "10.0", cvss.base_exploitability
    assert ("%.1f" % cvss.impact) == "8.5", cvss.impact
    assert cvss.base_score == "9.0", cvss.base_score
    assert cvss.score == "9.0", cvss.score
    assert cvss.base_vector == "AV:N/AC:L/Au:N/C:P/I:P/A:C", cvss.base_vector
    assert cvss.vector == "AV:N/AC:L/Au:N/C:P/I:P/A:C/E:ND/RL:U/RC:C/CDP:ND/TD:ND/CR:M/IR:M/AR:M", cvss.vector
    cvss = CVSS("AV:N/AC:L/Au:N/C:P/I:P/A:C/E:POC/RL:U/RC:UC")
    assert cvss.temporal_score == "7.3", cvss.temporal_score
    cvss = CVSS("C:P/I:P/A:C/E:POC/RL:U/RC:UC")
    assert cvss.temporal_score == "7.3", cvss.temporal_score
    assert "AV:N/AC:L/Au:N/C:P/I:P/A:C" in cvss.vector
    cvss.RC = cvss.CONFIRMED
    assert cvss.temporal_score == "8.1", cvss.temporal_score
    cvss.RL = cvss.TEMPORARY_FIX
    assert cvss.temporal_score == "7.3", cvss.temporal_score
    cvss.RL = cvss.OFFICIAL_FIX
    assert cvss.temporal_score == "7.0", cvss.temporal_score
    cvss = CVSS("AV:N/AC:L/Au:N/C:P/I:P/A:C/E:POC/RL:TF/RC:UC/CDP:MH/TD:H/CR:H/IR:H/AR:L")
    assert cvss.base_score == "9.0", cvss.base_score
    assert ("%.1f" % cvss.base_exploitability) == "10.0", cvss.base_exploitability
    assert ("%.1f" % cvss.impact) == "8.5", cvss.impact
    assert cvss.temporal_score == "6.6", cvss.temporal_score
    assert cvss.environmental_score == "7.8", cvss.environmental_score
    assert ("%.1f" % cvss.adjusted_impact) == "8.0", cvss.adjusted_impact
    assert cvss.score == "7.8", cvss.score

if __name__ == "__main__":
    import sys
    argv = sys.argv[1:]
    if argv:
        for vector in argv:
            try:
                print(CVSS_Base(vector))
            except ValueError:
                print(CVSS(vector))
    else:
        test()
