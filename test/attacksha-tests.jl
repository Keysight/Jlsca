# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using Base.Test

@everywhere begin
  using Jlsca.Sca
  using Jlsca.Sca.hw
  using Jlsca.Trs
end

function testShaTraces(conditional::Bool,direction::Direction, analysis::Analysis)
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
            trs = InspectorTrace(fullfilename)
            
            # samples are intermediates, convert to "leakage" here.
            addSamplePass(trs, x -> hw.(x))

            setPostProcessor(trs, CondAvg(SplitByTracesSliced()))
        else
          trs = InspectorTrace(fullfilename)

          # samples are intermediates, convert to "leakage" here.
          addSamplePass(trs, x -> hw.(x))
        end

        key = getKey(params, sca(trs,params,1, 100))

        @test(key == get(params.knownKey))
    end
end

x = CPA()
x.leakages = [HW()]

# @time testShaTraces(true, BACKWARD, x)
# @time testShaTraces(true, FORWARD, x)
@time testShaTraces(false, BACKWARD, x)
@time testShaTraces(false, FORWARD, x)

# x = LRA()
# x.basisModel = x -> basisModelSingleBits(x, 4)
# @time testShaTraces(true, FORWARD, x, true)
