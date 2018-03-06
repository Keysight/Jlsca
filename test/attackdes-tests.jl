# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using Base.Test

using Jlsca.Sca
using Jlsca.Trs

function testDesTraces(conditional::Bool,direction::Direction, analysis::Analysis, onetest::Bool=false, xor=false)
    tracedir = "../destraces"
    filenames = readdir(tracedir)

    for filename in filenames
        if filename[end-3+1:end] != "trs"
            continue
        end
        fullfilename = joinpath(tracedir,filename)
        @printf("file: %s\n", fullfilename)

        params = getParameters(fullfilename, direction)
        params.attack.xor = xor
        params.analysis = analysis

        # create Trace instance
        if conditional
            trs = InspectorTrace(fullfilename)

            setPostProcessor(trs, CondAvg(SplitByTracesSliced()))
        else
          trs = InspectorTrace(fullfilename)
        end

        key = getKey(params, sca(trs,params,1, 200))

        @test(key == get(params.knownKey))

        if onetest
          break
        end
    end
end

x = CPA()
x.leakages = [HW()]

@time testDesTraces(true, BACKWARD, x)
@time testDesTraces(true, FORWARD, CPA())
@time testDesTraces(false, BACKWARD, CPA())
@time testDesTraces(false, FORWARD, CPA())

x = LRA()
x.basisModel = x -> basisModelSingleBits(x, 4)
@time testDesTraces(true, FORWARD, x, true)

@time testDesTraces(false, BACKWARD, CPA(), false, true)
@time testDesTraces(false, FORWARD, CPA(), false, true)
