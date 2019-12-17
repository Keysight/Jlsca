# Play around with this for multi-processing, or call julia -p2
# addprocs(2)

using Distributed
@everywhere using Jlsca.Sca
@everywhere using Jlsca.Trs
@everywhere using Jlsca.Align

if length(ARGS) < 1
  print("no input trace\n")
  return
end

filename = ARGS[1]
direction = (length(ARGS) > 1 && ARGS[2] == "BACKWARD" ? BACKWARD : FORWARD)
params = getParameters(filename, direction)
if params == nothing
  error("Params cannot be derived from filename, assign and config your own here!")
  # params = DpaAttack(AesSboxAttack(),CPA())
end

params.analysis.postProcessor = CondReduce

@everywhere begin
    trs = InspectorTrace($filename)
    getTrs() = trs

    addSamplePass(trs, BitPass())
end

numberOfTraces = length(trs)

@time ret = sca(DistributedTrace(getTrs), params, 1, numberOfTraces)
