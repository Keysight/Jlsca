
using Sca
using Trs

import Sca.FORWARD,Sca.BACKWARD,Sca.PHASE1,Sca.PHASE2,Sca.SBOX,Sca.ROUNDOUT

# our vanilla  main function
function go()
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

  # create Trace instance
  trs = InspectorTrace(filename)

  # conditional averaging
  # setPostProcessor(trs, CondAvg, getNumberOfCandidates(params))
  setPostProcessor(trs, CondAvgLazyDict, getNumberOfCandidates(params))

  ret = sca(trs, params, 1, length(trs), false)
  Profile.print(maxdepth=9)

  return ret
end

import Base.sync_begin, Base.sync_end, Base.async_run_thunk

macro everyworker(ex)
    quote
        sync_begin()
        thunk = ()->(eval(Main,$(Expr(:quote,ex))); nothing)
        for pid in workers()
            async_run_thunk(()->remotecall_fetch(thunk, pid))
            yield() # ensure that the remotecall_fetch has been started
        end
        sync_end()
    end
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
    params = AesSboxAttack()
  end

  numberOfAverages = length(params.keyByteOffsets)
  numberOfCandidates = getNumberOfCandidates(params)

  @everyworker begin
      using Trs
      trs = InspectorTrace($filename)

      # maxShift = 20000
      # referenceOffset = 5000
      # reference = trs[1][2][referenceOffset:referenceOffset+5000]
      # corvalMin = 0.4
      # alignstate = CorrelationAlignFFT(reference, referenceOffset, maxShift)
      # addSamplePass(trs, x -> ((shift,corval) = correlationAlign(x, alignstate); corval > corvalMin ? circshift(x, shift) : Vector{eltype(x)}(0)))

      setPostProcessor(trs, CondAvg, $numberOfAverages, $numberOfCandidates)
  end

  numberOfTraces = @fetch length(Main.trs)

  ret = sca(DistributedTrace(), params, 1, numberOfTraces, false)
  # Profile.print(maxdepth=25,combine=true)

  return ret
end

# main function when called from Inspector
function jlsca4inspector(params::Attack)
  # read Inspector traces from stdin
  trs = InspectorTrace("-")

  numberOfAverages = length(params.keyByteOffsets)
  numberOfCandidates = getNumberOfCandidates(params)

  # enable conditional averaging
  setPostProcessor(trs, CondAvg, numberOfAverages, numberOfCandidates)

  # go baby go!
  return sca(trs, params, 1, length(trs), false)
end

############ hack your own code calling into jlsca below



function gf2dot(xx::Array{UInt8}, y::UInt8)
  return map(x -> gf2dot(x,y), xx)
end

function gf2dot(x::UInt8, y::UInt8)
  ret::UInt8 = 0

  for i in 0:7
    ret $= ((x >> i) & 1) & ((y >> i) & 1)
  end

  return ret
end

# uses the leakage models defined by Jakub Klemsa in his MSc thesis (see docs/Jakub_Klemsa---Diploma_Thesis.pdf) to attack Dual AES  implementations (see docs/dual aes.pdf)
function wb()
  if length(ARGS) < 1
    @printf("no input trace\n")
  end

  filename = ARGS[1]

  params = AesSboxAttack()
  params.mode = CIPHER
  params.direction = FORWARD
  params.dataOffset = 1
  params.analysis = DPA()
  params.analysis.leakageFunctions = [x -> gf2dot(x,UInt8(y)) for y in 1:255]

  # only 1 key byte at the time because 256 leakage models per candidate eats memory
  params.keyByteOffsets = [16]

  # create Trace instance
  trs = InspectorTrace(filename)

  # bit expand
  # addSamplePass(trs, tobits)

  # select only samples we need
  # addSamplePass(trs, (x -> x[1:2000]))

  # absolute
  # addSamplePass(trs, abs)

  # conditional averaging
  setPostProcessor(trs, CondAvg, getNumberOfCandidates(params))

  return sca(trs, params, 1, length(trs))
end




function condred()
  if length(ARGS) < 1
    @printf("no input trace\n")
  end

  filename = ARGS[1]
  direction::Direction = (length(ARGS) > 1 && ARGS[2] == "BACKWARD" ? BACKWARD : FORWARD)
  params = getParameters(filename, direction)
  if params == nothing
    params = DesSboxAttack()
    params.direction = BACKWARD
    params.dataOffset = 1
  end

  params.phases = [PHASE1]

  # params.phases = [PHASE2]
  # params.phaseInput = Nullable(hex2bytes("0000000004320a02"))

  params.targetType = SBOX #ROUNDOUT
  # params.analysis.leakageFunctions = [bit0, bit1, bit2, bit3]
  params.keyByteOffsets = [1]

  # create Trace instance
  trs = InspectorTrace(filename)

  # addDataPass(trs, x -> x[1:16])

  # addSamplePass(trs, x -> x[1:1000])

  # convert to (packed) bits
  addSamplePass(trs, tobits3)

  # conditional reduction
  setPostProcessor(trs, CondReduce, getNumberOfCandidates(params), trs)

  return sca(trs, params, 1, length(trs), false)
end

function condredfaster()
  if length(ARGS) < 1
    @printf("no input trace\n")
  end

  filename = ARGS[1]
  direction::Direction = (length(ARGS) > 1 && ARGS[2] == "BACKWARD" ? BACKWARD : FORWARD)
  params = getParameters(filename, direction)
  if params == nothing
    params = DesSboxAttack()
    params.direction = BACKWARD
    params.dataOffset = 1
  end

  params.phases = [PHASE1]

  # params.phases = [PHASE2]
  # params.phaseInput = Nullable(hex2bytes("0000000004320a02"))

  params.targetType = SBOX #ROUNDOUT
  # params.analysis.leakageFunctions = [bit0, bit1, bit2, bit3]
  params.keyByteOffsets = [1]

  numberOfAverages = length(params.keyByteOffsets)
  numberOfCandidates = getNumberOfCandidates(params)

  @everyworker begin
      using Trs
      trs = InspectorTrace($filename)
      addSamplePass(trs, tobits)
      setPostProcessor(trs, CondReduce, $numberOfAverages, $numberOfCandidates, trs)
  end

  numberOfTraces = @fetch length(Main.trs)

  ret = sca(DistributedTrace(), params, 1, numberOfTraces, false)
end


gofaster()
# condredfaster()
