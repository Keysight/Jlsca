# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using Base.Test

include("aes.jl")
include("dpa.jl")
include("lra.jl")
include("trs.jl")
include("sca-core.jl")
include("sca-scoring.jl")
include("sca-leakages.jl")
include("attackaes-core.jl")

function testAesTraces(conditional::Bool,direction::Direction, analysis::Analysis, onetest::Bool)
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
        @time trs = InspectorTrace(fullfilename)

        # bit expand
        # addSamplePass(trs, tobits)

        params.analysis = analysis
        if isa(params, AesSboxAttack) && isa(params.analysis, DPA)
            params.analysis.leakageFunctions = leakageFunctions
        elseif isa(params, AesMCAttack) && isa(params.analysis, DPA)
          params.analysis.leakageFunctions = [bit7]
        end

        if conditional
            setPostProcessor(trs, CondAvg, getNumberOfAverages(params))
        end

        key = sca(trs,params,1, 200)

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
