# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using Base.Test

include("des.jl")
include("conditional.jl")
include("dpa.jl")
include("lra.jl")
include("trs.jl")
include("sca-core.jl")
include("sca-scoring.jl")
include("sca-leakages.jl")
include("attackdes-core.jl")

function testDesTraces(conditional::Bool,direction::Direction, analysis::Analysis)
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
        params.analysis.leakageFunctions = [hw]
        # create Trace instance
        @time trs = InspectorTrace(fullfilename)

        # bit expand
        # addSamplePass(trs, tobits)

        # params.analysis = analysis

        if conditional
            setPostProcessor(trs, CondAvg, getNumberOfAverages(params))
        end

        key = sca(trs,params,1, 200)

        @test(key == get(params.knownKey))
    end
end

@time testDesTraces(true, BACKWARD, DPA())
@time testDesTraces(true, FORWARD, DPA())
@time testDesTraces(false, BACKWARD, DPA())
@time testDesTraces(false, FORWARD, DPA())
# @time testDesTraces(true, FORWARD, LRA())
