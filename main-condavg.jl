
using Sca
using Trs
using Align

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
    params = AesSboxAttack()
  end

  numberOfAverages = length(params.keyByteOffsets)
  numberOfCandidates = getNumberOfCandidates(params)

  @everyworker begin
      using Trs
      using Align
      trs = InspectorTrace($filename)

      # # example alignment pass
      # maxShift = 20000
      # referenceOffset = 5000
      # reference = trs[1][2][referenceOffset:referenceOffset+5000]
      # corvalMin = 0.4
      # alignstate = CorrelationAlignFFT(reference, referenceOffset, maxShift)
      # addSamplePass(trs, x -> ((shift,corval) = correlationAlign(x, alignstate); corval > corvalMin ? circshift(x, shift) : Vector{eltype(x)}(0)))

      setPostProcessor(trs, CondAvg(SplitByData($numberOfAverages, $numberOfCandidates)))
      # setPostProcessor(trs, CondAvg(SplitByTracesBlock()))
      # setPostProcessor(trs, IncrementalCorrelation(SplitByTracesSliced()))
  end

  numberOfTraces = @fetch length(Main.trs)

  ret = sca(DistributedTrace(), params, 1, numberOfTraces)

  return ret
end

@time gofaster()
