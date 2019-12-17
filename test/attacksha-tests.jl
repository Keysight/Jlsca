# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using Test
using Jlsca.Sca
using Jlsca.Sca:hw
using Jlsca.Trs

function testShaTraces(direction::Direction, analysis::Analysis)
    tracedir = "../shatraces"
    filenames = readdir(tracedir)

    for filename in filenames
        if filename[end-3+1:end] != "trs"
            continue
        end
        fullfilename = joinpath(tracedir,filename)
        print("file: $fullfilename\n")

        params = getParameters(fullfilename, direction)
        params.analysis = analysis

        trs = InspectorTrace(fullfilename)
        addSamplePass(trs, x -> hw.(x))

        key = getKey(params, sca(trs,params,1, 100))

        @test(key == params.knownKey)
    end
end

x = CPA()
x.leakages = [HW()]

@time testShaTraces(BACKWARD, x)
@time testShaTraces(FORWARD, x)

# x = LRA()
# x.basisModel = x -> basisModelSingleBits(x, 4)
# @time testShaTraces(FORWARD, x, true)
