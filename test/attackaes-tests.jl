# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using Base.Test

using Jlsca.Sca
using Jlsca.Trs

function testAesTraces(conditional::Bool,direction::Direction, analysis::Analysis, onetest::Bool=false, xor=false)
    tracedir = "../aestraces"
    filenames = readdir(tracedir)
    leakageFunctions = [HW()]

    for filename in filenames
        if filename[end-3+1:end] != "trs"
            continue
        end
        fullfilename = joinpath(tracedir,filename)
        @printf("file: %s\n", fullfilename)

        params = getParameters(fullfilename, direction)
        params.attack.xor = xor
        if isa(params.attack, AesMCAttack) && (params.attack.direction == BACKWARD || isa(analysis, LRA))
            continue
        end

        # create Trace instance
        if conditional
            trs = InspectorTrace(fullfilename)
            setPostProcessor(trs, CondAvg())
        else
          trs = InspectorTrace(fullfilename)
        end

        params.analysis = analysis
        if isa(params.attack, AesSboxAttack) && isa(params.analysis, CPA)
            params.analysis.leakages = leakageFunctions
        elseif isa(params.attack, AesMCAttack) && isa(params.analysis, CPA)
          params.analysis.leakages = [Bit(7)]
        end

        key = getKey(params, sca(trs,params,1, 200))

        @test(key == get(params.knownKey))

        if onetest
          break
        end
    end
end

@time testAesTraces(true, BACKWARD, CPA())
@time testAesTraces(true, FORWARD, CPA())
@time testAesTraces(false, BACKWARD, CPA())
@time testAesTraces(false, FORWARD, CPA())
@time testAesTraces(true, FORWARD, LRA(), true)

@time testAesTraces(false, BACKWARD, CPA(),false,true)
@time testAesTraces(false, FORWARD, CPA(),false,true)
