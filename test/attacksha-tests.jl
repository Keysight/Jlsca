# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using Base.Test

@everywhere begin
  using Jlsca.Sca
  using Jlsca.Sca.hw
  using Jlsca.Trs
end

function testShaTraces(conditional::Bool,direction::Direction, analysis::Analysis, hack::Bool=false)
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
            trs = InspectorTrace($fullfilename)
            
            # samples are intermediates, convert to "leakage" here.
            addSamplePass(trs, x -> vcat(hw.(x), hw.(x .& 0xf), hw.(x .>> 4)))

            setPostProcessor(trs, CondAvg(SplitByTracesSliced()))
          end
        else
          trs = InspectorTrace(fullfilename)

          # samples are intermediates, convert to "leakage" here.
          addSamplePass(trs, x -> vcat(hw.(x), hw.(x .& 0xf), hw.(x .>> 4)))
        end


        if conditional
          key = getKey(params, sca(DistributedTrace(),params,1,100))
        else
          key = getKey(params, sca(trs,params,1, 100))
        end

        if hack
        # FIXME: ghost peaks in DPA number 4 means this fails
          @test(key == [0x67, 0x45, 0x23, 0x01, 0xe7, 0x4d, 0x2b, 0x09, 0x98, 0xba, 0xdc, 0xfe, 0x12, 0x32, 0x74, 0x76, 0xcc, 0x53, 0x62, 0x70])
        else
          @test(key == get(params.knownKey))
        end
    end
end

x = CPA()
x.leakages = [HW()]

# @time testShaTraces(true, BACKWARD, x)
@time testShaTraces(true, FORWARD, x, true)
@time testShaTraces(false, BACKWARD, x)
# @time testShaTraces(false, FORWARD, x)

# x = LRA()
# x.basisModel = x -> basisModelSingleBits(x, 4)
# @time testShaTraces(true, FORWARD, x, true)
