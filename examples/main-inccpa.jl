
using Jlsca.Sca
using Jlsca.Trs
using Jlsca.Align

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

  params.analysis = IncrementalCPA()
  if isa(params.attack, AesMCAttack)
    params.analysis.leakages = [Bit(i) for i in 0:31]
  else
    if isa(params.attack, AesSboxAttack)
      params.analysis.leakages = [Bit(i) for i in 0:7]
    elseif isa(params.attack, DesSboxAttack)
      params.analysis.leakages = [HW()]
    end
  end

  @everyworker begin
      using Jlsca.Trs
      using Jlsca.Align

      trs = InspectorTrace($filename)

      # # example alignment pass
      # maxShift = 20000
      # referenceOffset = 5000
      # reference = trs[1][2][referenceOffset:referenceOffset+5000]
      # corvalMin = 0.4
      # alignstate = CorrelationAlignFFT(reference, referenceOffset, maxShift)
      # addSamplePass(trs, x -> ((shift,corval) = correlationAlign(x, alignstate); corval > corvalMin ? circshift(x, shift) : Vector{eltype(x)}(0)))

      setPostProcessor(trs, IncrementalCorrelation(SplitByTracesBlock()))
      # setPostProcessor(trs, IncrementalCorrelation(SplitByTracesSliced()))
  end

  numberOfTraces = @fetch length(Main.trs)
  if length(ARGS) > 1
    numberOfTraces = min(parse(ARGS[2]), numberOfTraces)
  end


  ret = sca(DistributedTrace(), params, 1, numberOfTraces)

  return ret
end

@time gofaster()
