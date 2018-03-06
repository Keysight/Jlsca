# Play around with this for multi-processing. IncrementalCPA benefits also from threading, tweak env variable JULIA_NUM_THREADS
# addprocs(2)

@everywhere begin
  using Jlsca.Sca
  using Jlsca.Trs
  using Jlsca.Align
end

# our vanilla  main function
function gofaster()
  if length(ARGS) < 1
    @printf("no input trace\n")
    return
  end

  filename = ARGS[1]
  direction::Direction = (length(ARGS) > 1 && ARGS[2] == "BACKWARD" ? BACKWARD : FORWARD)
  params = getParameters(filename, direction)
  if params == nothing
    throw(ErrorException("Params cannot be derived from filename, assign and config your own here!"))
    # params = DpaAttack(AesSboxAttack(),IncrementalCPA())
  end

  analysis = IncrementalCPA()
  analysis.leakages = params.analysis.leakages
  params.analysis = analysis

  @everywhere begin
      trs = InspectorTrace($filename)

      setPostProcessor(trs, IncrementalCorrelation(SplitByTracesBlock()))
  end

  numberOfTraces = length(trs)

  ret = sca(DistributedTrace(), params, 1, numberOfTraces)

  return ret
end

@time gofaster()
