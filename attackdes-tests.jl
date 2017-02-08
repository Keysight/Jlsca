# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using Base.Test

using Sca
using Trs

import Sca.FORWARD,Sca.BACKWARD,Sca.PHASE1,Sca.PHASE2,Sca.PHASE3,Sca.PHASE4,Sca.PHASE5,Sca.PHASE6,Sca.SBOX,Sca.ROUNDOUT,Sca.TDES1,Sca.TDES2,Sca.TDES3

function testDesTraces(conditional::Bool,direction::Direction, analysis::Analysis, onetest::Bool=false)
    tracedir = "destraces"
    filenames = readdir(tracedir)
    # leakageFunctions = [bit7]

    for filename in filenames
        if filename[end-3+1:end] != "trs"
            continue
        end
        fullfilename = joinpath(tracedir,filename)
        @printf("file: %s\n", fullfilename)

        params = getParameters(fullfilename, direction)
        params.analysis = analysis
        # params.analysis.leakageFunctions = [hw]
        # create Trace instance
        if conditional
          @everyworker begin
            using Trs
            trs = InspectorTrace($fullfilename)

            setPostProcessor(trs, CondAvg(SplitByTracesSliced()))
          end
        else
          trs = InspectorTrace(fullfilename)
        end


        if conditional
          key = sca(DistributedTrace(),params,1,200)
        else
          key = sca(trs,params,1, 200)
        end

        @test(key == get(params.knownKey))

        if onetest
          break
        end
    end
end

x = DPA()
x.leakageFunctions = [hw]

@time testDesTraces(true, BACKWARD, x)
@time testDesTraces(true, FORWARD, DPA())
@time testDesTraces(false, BACKWARD, DPA())
@time testDesTraces(false, FORWARD, DPA())

x = LRA()
x.basisModel = x -> basisModelSingleBits(x, 4)
@time testDesTraces(true, FORWARD, x, true)
