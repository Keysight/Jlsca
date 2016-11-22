# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

include("aes.jl")
include("des.jl")
include("conditional.jl")
include("dpa.jl")
include("lra.jl")
include("trs.jl")

module Sca

include("sca-core.jl")
include("sca-leakages.jl")
include("sca-scoring.jl")
include("attackaes-core.jl")
include("attackdes-core.jl")

# our vanilla  main function
function go()
  if length(ARGS) < 1
    @printf("no input trace\n")
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
  setPostProcessor(trs, CondAvg, getNumberOfAverages(params))

  return sca(trs, params, 1, length(trs), false)
end

# main function when called from Inspector
function jlsca4inspector(params::Attack)
  # read Inspector traces from stdin
  trs = InspectorTrace("-")

  # enable conditional averaging
  setPostProcessor(trs, CondAvg, getNumberOfAverages(params))

  # go baby go!
  return sca(trs, params, 1, length(trs), false)
end

############ hack your own code calling into jlsca below

# some helpers that need to go somewhere else
function bitcompress(O::Matrix)
  (ro,co) = size(O)
  keep = ones(Bool, co)

  progress = Progress(convert(Int, co*(co-1)/2), 1)

  for c1 in 1:co
    if var(O[:,c1]) < .2
        keep[c1] = false
    end
    for c2 in c1+1:co
      if keep[c1] && O[:,c1] == O[:,c2]
        keep[c1] = false
      end
      next!(progress)
    end
  end

  columns = find(keep)
  ret = zeros(eltype(O), ro, length(columns))

  for c in 1:length(columns)
    ret[:,c] = O[:,columns[c]]
  end

  return ret
end

function tobits(x::Vector)
  ret = zeros(length(x)*8)
  for i in 1:length(x)
    for j in 1:8
      ret[(i-1)*8+j] = (x[i] >> (j-1)) & 1
    end
  end
  return ret
end

r = 0

function mytest(data,w,offset)
  global r
    input = vec(data[offset+1:offset+16])
    output = vec(data[offset+17:offset+32])

    expectedoutput = Aes.Cipher(input, w)

    if expectedoutput != output
      @printf("trace idx %d, bad data: %s\n", r, bytes2hex(vec(data[:])))
    end
    r += 1

    return []
end

function verify()
  if length(ARGS) < 1
    @printf("no input trace\n")
  end

  filename = ARGS[1]

  key = hex2bytes("deadbeef01234567cafebabe89abcdef")
  w = Aes.KeyExpansion(key, 10, 4)

  trs = InspectorTrace(filename)

  addSamplePass(trs, x->[])
  addDataPass(trs, x -> mytest(x,w,0))

  (data,samples) = readAllTraces(trs, 1000000)

end

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
  setPostProcessor(trs, CondAvg, getNumberOfAverages(params))

  return sca(trs, params, 1, length(trs))
end


function abssumscore(col::Vector{Float64})
  conf::Float64 = 0
  threshold = 2 / sqrt(500)
  for i in col
    if abs(i) > threshold
      conf += abs(i) - threshold
    end
  end
  return conf
end

function iszeros(fname)
  f = open(fname, "r")
  data = read(fname)
  close(f)

  if var(data) == 0.0
    rm(fname)
    return true
  end

  (numberOfSamplesPerTrace, sampleType, numberOfTraces1) = parseSamplesFilename(fname)
  data = reshape(data, (numberOfSamplesPerTrace, numberOfTraces1))

  for i in 2:numberOfTraces1
    if data[:,i] != data[:,i-1]
      return false
    end
  end

  rm(fname)
  return true
end

# uses one data file with data, and does CPA on a directory with sample data files. The hammer.
function hammer()
  if length(ARGS) < 1
    @printf("no input trace\n")
  end

  datafilename = ARGS[1]

  params = DesSboxAttack()
  params.mode = DES
  params.encrypt = true
  params.direction = BACKWARD
  params.analysis = DPA()

  # better to take one bit, since we're forced to cut up the sample inputs in columns of "maxSamples" size. If you take more than one leakage model it may cross the column boundary.
  params.analysis.leakageFunctions = [bit0]

  params.dataOffset = 1
  params.phases = [PHASE1]

  # only 1 key byte
  params.keyByteOffsets = [1]

  # the max column width, since it's *8 due to bit expand you want to be careful here
  maxSamples = 100000

  if length(ARGS) < 2
    @printf("need data file and [one directory | one or more samples files]\n")
    return
  end

  if isdir(ARGS[2])
    entries = readdir(ARGS[2])
  else
    entries = ARGS[2:end]
  end

  # @printf("entries in directory: %d\n", length(entries))

  for i in 1:length(entries)
    m = match(r"samples.*\.bin$"m, entries[i])
    if m == nothing
      continue
    end
    if isdir(ARGS[2])
      samplesfilename = joinpath(ARGS[2], entries[i])
    else
      samplesfilename = entries[i]
    end

    @printf("file: %s\n", entries[i])

    # if iszeros(samplesfilename)
    #   @printf("removed %s\n", samplesfilename)
    #   continue
    # end

    # create Trace instance
    # trs = SplitBinary(datafilename, 8, samplesfilename, 288, 16)
    trs = SplitBinary(datafilename, samplesfilename)
    # (numberOfSamplesPerTrace, sampleType, numberOfTraces1) = Trs.parseFilename(samplesfilename)
    numberOfSamplesPerTrace  = length(trs[1][2])

    blocks = div(numberOfSamplesPerTrace-1, maxSamples)

    @printf("blocks: %d\n", blocks)

    for b in 1:(blocks+1)

      if blocks > 0
        if b < (blocks+1)
          nrSamples = maxSamples
        else
          nrSamples = numberOfSamplesPerTrace - blocks*maxSamples
        end

        start = (((b-1)*maxSamples)+1)
        sampleRange = start:(start+nrSamples-1)

        @printf("samplerange: %s\n", string(sampleRange))

        addSamplePass(trs, (x -> x[sampleRange]))
      end

      # bit expand
      addSamplePass(trs, tobits)

      # conditional averaging
      # setPostProcessor(trs, CondAvg, getNumberOfAverages(params))

      t::Task = @task scatask(trs, params, 1, length(trs))

      try
        for (status, statusData) in t
          if status == INTERMEDIATESCORES
            (scoresAndOffsets, numberOfTraces2, numberOfSamples, dataWidth, keyOffsets, knownKey) = statusData
            scoresfile = @sprintf("%s_%d.txt", samplesfilename, b)

            open(x -> printScores(scoresAndOffsets, dataWidth, keyOffsets, numberOfTraces2, numberOfSamples, (+), knownKey, false,  5, x), scoresfile, "w")

            # printScores(scoresAndOffsets, dataWidth, keyOffsets, numberOfTraces2, numberOfSamples, (+), knownKey, false,  5)

            # Profile.print(maxdepth=8)


            if !isnull(params.outputkka) && !isnull(params.knownKey)
              add2kka(scoresAndOffsets, dataWidth, keyOffsets, numberOfTraces2, numberOfSamples, get(knownKey), "blerp.txt")
            end
          else
            @printf("WARNING: don't know how to handle %s produced by scatask for %s\n", string(status), string(params))
          end
        end
      catch e
        if t.exception != nothing
          @printf("Task blew up: %s", t.exception)
          Base.show_backtrace(STDOUT, t.backtrace)
          @printf("\n")
        end
        rethrow(e)
      end

      popSamplePass(trs)

      if blocks > 0
        popSamplePass(trs)
      end

    end
  end
end

function mccees()
  if length(ARGS) < 2
    @printf("no input trace\n")
  end

  FFTW.set_num_threads(Sys.CPU_CORES)

  params = AesSboxAttack()
  # params.xor = true
  params.mode = CIPHER
  params.direction = FORWARD
  params.dataOffset = 1
  params.analysis = DPA()
  # params.analysis.leakageFunctions = [hw]
  params.analysis.leakageFunctions = [(x -> (x .>> i) & 1) for i in 0:7]
  params.keyByteOffsets = [1]

  # params = AesSboxAttack()
  # params.mode = CIPHER
  # # params.xor = true
  # params.direction = BACKWARD
  # params.dataOffset = 17
  # params.analysis = DPA()
  # # params.analysis.leakageFunctions = [hw]
  # params.analysis.leakageFunctions = [(x -> (x .>> i) & 1) for i in 0:7]
  # params.keyByteOffsets = [1]
  #
  # params = AesMCAttack()
  # # params.xor = true
  # params.mode = CIPHER
  # params.direction = FORWARD
  # params.dataOffset = 1
  # params.analysis = DPA()
  # params.analysis.leakageFunctions = [(x -> (x .>> i) & 1) for i in 0:31]


  params.knownKey = Nullable(hex2bytes("cafebabedeadbeef0001020304050607"))

  # create Trace instance
  # trs = SplitBinary("pipo_data_32s.bin","pipo_samples_Int16_3300s.bin")
  trs = InspectorTrace("mc.trs")
  len = 100000
  # bit expand
  # addSamplePass(trs, tobits)

  # select only samples we need
  # addSamplePass(trs, (x -> x[1:2000]))

  # align
  maxShift = 1000
  referenceOffset = 1447
  reference = trs[1][2][referenceOffset:referenceOffset+60]
  corvalMin = 0.4
  # addSamplePass(trs, x -> ((shift,corval) = correlationAlign(x, reference, referenceOffset, maxShift); corval > corvalMin ? circshift(x, shift) : nothing))
  reference0mean = reference - mean(reference)
  reversereference0mean = reverse(reference0mean)
  square_sum_x2 = sqrt(sum(reference0mean .^ 2))
  window = max(1, referenceOffset - maxShift):(min(referenceOffset + maxShift + length(reference), length(trs[1][2])))
  sums_y = zeros(Float64, length(window)+1)
  sums_y2 = zeros(Float64, length(window)+1)
  np = Ref{Base.DFT.FFTW.rFFTWPlan}()
  addSamplePass(trs, x -> ((shift,corval) = @profile correlationAlign2(x, reference0mean, reversereference0mean, referenceOffset, maxShift, window, square_sum_x2, sums_y, sums_y2, np); corval > corvalMin ? circshift(x, shift) : nothing))

  # absolute
  addSamplePass(trs, abs)

  # conditional averaging
  setPostProcessor(trs, CondAvg, getNumberOfAverages(params))

  ret = sca(trs, params, 1, len)
  Profile.print(maxdepth=9)

end

function correlationAlign(samples::Vector, reference::Vector, referenceOffset::Int, maxShift::Int)
  align::Int = 0
  maxCorr::Float64 = 0
  window = max(1, referenceOffset - maxShift):(min(referenceOffset + maxShift + length(reference), length(samples)) - length(reference) + 1)
  # @printf("window: %s\n", string(window))
  for o in window
    e = o + length(reference) - 1
    corr = cor(samples[o:e], reference)
    if corr > maxCorr
      maxCorr = corr
      align = o
    end
  end

  ret = (referenceOffset-align,maxCorr)
  # @printf("%s\n", ret)
  return ret
end

function blerpconv{T<:Base.LinAlg.BlasFloat}(u::StridedVector{T}, v::StridedVector{T}, np::Ref{Base.DFT.FFTW.rFFTWPlan})
    nu = length(u)
    nv = length(v)
    n = nu + nv - 1
    np2 = n > 1024 ? nextprod([2,3,5], n) : nextpow2(n)
    upad = [u; zeros(T, np2 - nu)]
    vpad = [v; zeros(T, np2 - nv)]
    if T <: Real
      # p = plan_rfft(upad)
      # y = irfft((p*upad).*(p*vpad), np2)
      if !isdefined(np, :x)
        @printf("once!\n")
        np.x = plan_rfft(upad, flags=FFTW.PRESERVE_INPUT)
      end
      p = np.x
      y = irfft((p*upad).*(p*vpad), np2)
    else
        p = plan_fft!(upad)
        y = ifft!((p*upad).*(p*vpad))
    end
    return y[1:n]
end


function correlationAlign2(samples::Vector, reference0mean::Vector, reversereference0mean::Vector, referenceOffset::Int, maxShift::Int, window::Range, square_sum_x2::Float64, sums_y::Vector{Float64}, sums_y2::Vector{Float64}, np::Ref{Base.DFT.FFTW.rFFTWPlan})
  align::Int = 0
  maxCorr::Float64 = 0
  # window = max(1, referenceOffset - maxShift):(min(referenceOffset + maxShift + length(reference), length(samples)))
  # @printf("window: %s\n", window)

  # reference0mean = reference - mean(reference)
  # square_sum_x2 = sqrt(sum(reference0mean .^ 2))
  # sums_y = zeros(Float64, length(window)+1)
  # sums_y2 = zeros(Float64, length(window)+1)

  # cv = blerpconv(float(samples[window]), reversereference0mean, np)
  cv = blerpconv(reversereference0mean, float(samples[window]), np)
  n = length(reference0mean)

  # @printf("cv: %s\n", string(cv))
  # cv = cv[n:(end-n+1)]
  # @printf("cv stripped: %s\n", string(cv))

  idx = 2
  for i in window
    s::Float64 = samples[i]
    sums_y[idx] = sums_y[idx-1] + s
    sums_y2[idx] =  sums_y2[idx-1] + (s ^ 2)
    idx += 1
  end

  # @printf("sums_y %s\n", string(sums_y))
  # @printf("sums_y2 %s\n", string(sums_y2))

  for i in 1:(length(window)-length(reference0mean)+1)
    sum_x_y = cv[n+i-1]
    sum_y2 = sums_y2[i+n] - sums_y2[i]
    sum_y = sums_y[i+n] - sums_y[i]
    # @printf("sum_x_y %s, square_sum_x2 %s, sum_y2 %s, sum_y %s\n", string(sum_x_y), string(square_sum_x2), string(sum_y2), string(sum_y))
    argh = sum_y2 - (sum_y ^ 2)/n
    r::Float64 = sum_x_y / (square_sum_x2 * sqrt(argh))
    # @printf("r: %s\n", string(r))
    if r > maxCorr
      maxCorr = r
      align = window[i]
    end
  end

  ret = (referenceOffset-align,maxCorr)
  # @printf("%s\n", ret)
  return ret
end

# function correlationAlignThreaded(samples::Vector, reference::Vector, referenceOffset::Int, maxShift::Int)
#   align::Int = 0
#   maxCorr::Float64 = 0
#   window = max(1, referenceOffset - maxShift):(min(referenceOffset + maxShift + length(reference), length(samples)) - length(reference) + 1)
#   maxCorrs = zeros(Float64, Threads.nthreads())
#   aligns = zeros(Int, Threads.nthreads())
#   # @printf("window: %s\n", string(window))
#   for o in window
#     tid = Thread.threadid()
#     e = o + length(reference) - 1
#     corr = cor(samples[o:e], reference)
#     if corr > maxCorrs[tid]
#       maxCorrs[tid] = corr
#       aligns[tid] = o
#     end
#   end
#
#   ret = (referenceOffset-align,maxCorr)
#   # @printf("%s\n", ret)
#   return ret
# end

function applyAlign(samples::Vector, alignments::Vector{Tuple{Int,Float64}}, minCorval::Float64, idxptr::Ref{Int}, len::Int)
  idx = idxptr.x
  idxptr.x += 1
  if idxptr.x == len + 1
    idxptr.x = 1
  end
  shift,corval = alignments[idx]
  if corval > minCorval
    return circshift(samples,shift)
  end
  @printf("dropping idx %d %s\n", idx, string(alignments[idx]))
end

function storeAlign(samples::Vector, alignFn::Function, alignments::Vector{Tuple{Int,Float64}}, idx::Ref{Int}, len::Int)
  alignments[idx.x] = alignFn(samples)
  idx.x += 1
  if idx.x == len + 1
    idx.x = 1
  end
  return samples
end


# end of module
end
