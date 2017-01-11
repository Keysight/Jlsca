# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Authors: Cees-Bart Breunesse
#
# We reduce sample space by exploiting the assumption that samples
# representing the bits of the value of a specific target variable do not vary for inputs that create
# the same bits for that target variable.
#
# This is the same assumption under which conditional averaging works, but
# instead of averaging we simply remove columns where the samples are different between two traces
# where the target variable on which we're reducing is the same.

# This is important in a WBC scenario since you typically deal will a small amount of very long
# traces. Thus:
# - conditional averaging reduce the #traces
# - bitwise conditional reduction reduces the #traces and #samples
#
# This approach does not work on ciphers that use widening encodings or random masks.
export CondReduce,tobits

using ProgressMeter

type CondReduce <: Cond
  mask::Dict{Int,BitVector}
  traceIdx::Dict{Int,Dict{Int,Int}}
  globcounter::Int
  numberOfAverages::Int
  numberOfCandidates::Int
  worksplit::WorkSplit
  range::Range
  trs::Trace

  function CondReduce(numberOfAverages::Int, numberOfCandidates::Int, trs::Trace)
    mask = Dict{Int,BitVector}()
    traceIdx = Dict{Int,Dict{Int,Int}}()
    worksplit = WorkSplit(numberOfAverages, numberOfCandidates)
    range = getWorkerRange(worksplit)
    @printf("Conditional bitwise sample reduction, handling data range %s\n", range)

    new(mask, traceIdx, 0, numberOfAverages, numberOfCandidates, worksplit, range, trs)
  end
end

# only works on samples of BitVector type, do addSamplePass(trs, tobits)
# to create this input efficiently!
function add(c::CondReduce, trs::Trace, traceIdx::Int)
  data::AbstractVector = getData(trs, traceIdx)
  samples = Nullable{Vector{trs.sampleType}}()

  if length(data) == 0
    return
  end

  for idx in eachindex(data)
    val = data[idx]

    if !(toVal(c.worksplit, Int(idx), Int(val)) in c.range)
      continue
    end

    if isnull(samples)
     samples = Nullable(getSamples(trs, traceIdx))
     if length(get(samples)) == 0
       return
     end
    end

    if !haskey(c.mask, idx)
      c.mask[idx] = trues(length(get(samples)))
      c.traceIdx[idx] = Dict{Int,Int}()
    end

    if !haskey(c.traceIdx[idx], val)
      c.traceIdx[idx][val] = traceIdx
    end

    currmask = c.mask[idx]
    idxes = find(currmask)
    maskidxes = idxes[find(trs[c.traceIdx[idx][val]][2][idxes] $ get(samples)[idxes])]
    currmask[maskidxes] .= false
  end

  c.globcounter += 1
end

function merge(this::CondReduce, other::CondReduce)
  for (idx,dictofavgs) in other.traceIdx
    if !haskey(this.traceIdx, idx)
      this.traceIdx[idx] = dictofavgs
    else
      for (val, avg) in dictofavgs
        if val in keys(this.traceIdx[idx])
          throw(ErrorException("fixme"))
        else
          this.traceIdx[idx][val] = avg
        end
      end
    end
  end

  for (idx,msk) in other.mask
    if !haskey(this.mask, idx)
      this.mask[idx] = msk
    else
      this.mask[idx] &= msk
    end
  end
end

function get(c::CondReduce)
  if nprocs() > 1
    for worker in workers()
      if worker == c.worksplit.worker
        continue
      else
        other = @fetchfrom worker Main.trs.postProcInstance
        merge(c, other)
      end
    end
  end

  datas = Matrix[]
  reducedsamples = Matrix[]

  maxVal = 0
  for k in keys(c.traceIdx)
    maxVal = max(maxVal, findmax(keys(c.traceIdx[k]))[1])
  end

  if maxVal <= 2^8
    dataType = UInt8
  elseif maxVal <= 2^16
    dataType = UInt16
  else
    throw(Exception("Unsupported and not recommended ;)"))
  end

  for k in sort(collect(keys(c.traceIdx)))
    dataSnap = collect(dataType, keys(c.traceIdx[k]))
    idxes = find(c.mask[k])
    sampleSnap = BitArray{2}(length(dataSnap), length(idxes))

    for j in 1:length(dataSnap)
      trsIndex = c.traceIdx[k][dataSnap[j]]
      samples = getSamples(c.trs, trsIndex)
      sampleSnap[j,:] = samples[idxes]
    end

    dataSnap = reshape(convert(Array{dataType,1}, dataSnap), length(dataSnap),1)
    push!(datas, dataSnap)
    push!(reducedsamples, sampleSnap)
  end

  @printf("\nReduced %d input traces, %s data type\n", c.globcounter, string(dataType))

  return (datas,reducedsamples)
end

function getGlobCounter(c::CondReduce)
  return c.globcounter
end

function tobits(x::Vector{UInt8})
  bits = length(x)*8
  discard = bits % 64
  if discard > 0
    @printf("found %d bits, but discarding %d bits, please 64 bit align your samples", bits, discard)
    warned = true
  end

  # this is a fast hack to create BitVectors
  a = BitVector()
  a.chunks = reinterpret(UInt64, x)
  a.len = bits - discard
  a.dims = (0,)

  return a
end
