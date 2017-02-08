# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using Base.Test

using Sca
using Trs

import Sca.FORWARD,Sca.BACKWARD,Sca.PHASE1,Sca.PHASE2,Sca.PHASE3,Sca.PHASE4,Sca.PHASE5,Sca.PHASE6,Sca.SBOX,Sca.ROUNDOUT,Sca.TDES1,Sca.TDES2,Sca.TDES3

function testAesTraces(conditional::Bool,direction::Direction, analysis::Analysis, onetest::Bool=false)
    tracedir = "aestraces"
    filenames = readdir(tracedir)
    leakageFunctions = [hw]

    for filename in filenames
        if filename[end-3+1:end] != "trs"
            continue
        end
        fullfilename = joinpath(tracedir,filename)
        @printf("file: %s\n", fullfilename)

        params = getParameters(fullfilename, direction)
        if isa(params, AesMCAttack) && (params.direction == BACKWARD || isa(analysis, LRA))
            continue
        end

        # create Trace instance
        if conditional
          @everyworker begin
            using Trs
            trs = InspectorTrace($fullfilename)

            # bit expand
            # addSamplePass(trs, tobits)

            setPostProcessor(trs, CondAvg(SplitByTracesSliced()))
          end
        else
          trs = InspectorTrace(fullfilename)
        end

        params.analysis = analysis
        if isa(params, AesSboxAttack) && isa(params.analysis, DPA)
            params.analysis.leakageFunctions = leakageFunctions
        elseif isa(params, AesMCAttack) && isa(params.analysis, DPA)
          params.analysis.leakageFunctions = [bit7]
        end

        if conditional
          key = sca(DistributedTrace(),params,1, 200, false)
        else
          key = sca(trs,params,1, 200, false)
        end

        @test(key == get(params.knownKey))

        if onetest
          break
        end
    end
end

@time testAesTraces(true, BACKWARD, DPA())
@time testAesTraces(true, FORWARD, DPA())
@time testAesTraces(false, BACKWARD, DPA())
@time testAesTraces(false, FORWARD, DPA())
@time testAesTraces(true, FORWARD, LRA(), true)
