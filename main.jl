# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

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

  return sca(trs, params, 1, length(trs)))
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

    if iszeros(samplesfilename)
      @printf("removed %s\n", samplesfilename)
      continue
    end

    # create Trace instance
    # trs = SplitBinary(datafilename, 8, samplesfilename, 288, 16)
    trs = SplitBinary(datafilename, samplesfilename)
    (numberOfSamplesPerTrace, sampleType, numberOfTraces1) = parseSamplesFilename(samplesfilename)

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

            # open(x -> printScores(scoresAndOffsets, dataWidth, keyOffsets, numberOfTraces2, numberOfSamples, (+), knownKey, false,  5, x), scoresfile, "w")

            @profile printScores(scoresAndOffsets, dataWidth, keyOffsets, numberOfTraces2, numberOfSamples, (+), knownKey, false,  5)

            Profile.print(maxdepth=8)


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
