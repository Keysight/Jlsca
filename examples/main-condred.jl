# Play around with this for multi-processing.
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
    # params = DpaAttack(AesSboxAttack(),LRA())
  end

  @everywhere begin
      trs = InspectorTrace($filename,true)

      addSamplePass(trs, BitPass())

      setPostProcessor(trs, CondReduce(SplitByTracesBlock()))
  end

  numberOfTraces = length(trs)

  ret = sca(DistributedTrace(), params, 1, numberOfTraces)

  return ret
end

@time gofaster()
