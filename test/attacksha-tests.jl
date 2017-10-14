# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using Base.Test

using Jlsca.Sca
using Jlsca.Trs

function testShaTraces(conditional::Bool,direction::Direction, analysis::Analysis, onetest::Bool=false)
    tracedir = "../shatraces"
    filenames = readdir(tracedir)

    for filename in filenames
        if filename[end-3+1:end] != "trs"
            continue
        end
        fullfilename = joinpath(tracedir,filename)
        @printf("file: %s\n", fullfilename)

        params = getParameters(fullfilename, direction)
        params.analysis = analysis

        # create Trace instance
        if conditional
          @everyworker begin
            using Jlsca.Trs
            trs = InspectorTrace($fullfilename)

            setPostProcessor(trs, CondAvg(SplitByTracesSliced()))
          end
        else
          trs = InspectorTrace(fullfilename)
        end


        if conditional
          key = sca(DistributedTrace(),params,1,100)
        else
          key = sca(trs,params,1, 100)
        end

        @test(key == get(params.knownKey))

        if onetest
          break
        end
    end
end

x = CPA()
x.leakages = [HW()]

@time testShaTraces(true, BACKWARD, x)
@time testShaTraces(true, FORWARD, x)
@time testShaTraces(false, BACKWARD, x)
@time testShaTraces(false, FORWARD, x)

# x = LRA()
# x.basisModel = x -> basisModelSingleBits(x, 4)
# @time testShaTraces(true, FORWARD, x, true)
