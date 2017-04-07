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
#
# Duplicate column removal by Ruben Muijrers

export CondReduce


type CondReduce <: Cond
  mask::Dict{Int,BitVector}
  traceIdx::Dict{Int,Dict{Int,Int}}
  globcounter::Int
  worksplit::WorkSplit
  trs::Trace
  bitcompressedInitialized::Bool
  state::BitCompress

  function CondReduce(trs::Trace)
    CondReduce(NoSplit(), trs)
  end

  function CondReduce(worksplit::WorkSplit, trs::Trace)
    mask = Dict{Int,BitVector}()
    traceIdx = Dict{Int,Dict{Int,Int}}()
    # @printf("Conditional bitwise sample reduction, split %s\n", worksplit)

    new(mask, traceIdx, 0, worksplit, trs, false)
  end
end

function reset(c::CondReduce)
  c.mask = Dict{Int,BitVector}()
  c.traceIdx = Dict{Int,Dict{Int,Int}}()
  c.globcounter = 0
  c.bitcompressedInitialized = true
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

    if isa(c.worksplit, SplitByData) && !(toVal(c.worksplit, Int(idx), Int(val)) in c.worksplit.range)
      continue
    end

    if isnull(samples)
     samples = Nullable(getSamples(trs, traceIdx))
     if length(get(samples)) == 0
       return
     end

     if !c.bitcompressedInitialized
       c.state = BitCompress(length(get(samples)))
       c.bitcompressedInitialized = true
     end

     bitcompress(c.state, get(samples))
    end

    if !haskey(c.mask, idx)
      c.mask[idx] = trues(length(get(samples)))
      c.traceIdx[idx] = Dict{Int,Int}()
    end

    if !haskey(c.traceIdx[idx], val)
      c.traceIdx[idx][val] = traceIdx
      continue
    end

    cachedreftrace = getSamples(trs, c.traceIdx[idx][val])
    cachedsamples = get(samples)

    cachedreftrace $= cachedsamples
    c.mask[idx][:] &= !(c.mask[idx] & cachedreftrace)
    cachedsamples = nothing
    cachedreftrace = nothing

  end

  c.globcounter += 1
end

function merge(this::CondReduce, other::CondReduce)
  if isa(this.worksplit, SplitByTraces)
    this.globcounter += other.globcounter
  end

  for (idx,dictofavgs) in other.traceIdx
    if !haskey(this.traceIdx, idx)
      this.traceIdx[idx] = dictofavgs
      this.mask[idx] = other.mask[idx]
      this.state = other.state
    else
      this.mask[idx][:] &= other.mask[idx]
      for (val, avg) in dictofavgs
        if val in keys(this.traceIdx[idx])
          if this.traceIdx[idx][val] != other.traceIdx[idx][val]
            cachedreftrace = getSamples(this.trs, this.traceIdx[idx][val])
            cachedsamples = getSamples(this.trs, other.traceIdx[idx][val])

            cachedreftrace $= cachedsamples
            this.mask[idx][:] &= !(this.mask[idx] & cachedreftrace)

            bitcompress(this.state, cachedsamples)
          end
        else
          cachedsamples = getSamples(this.trs, other.traceIdx[idx][val])
          bitcompress(this.state, cachedsamples)

          this.traceIdx[idx][val] = other.traceIdx[idx][val]
        end
      end
    end
  end
end

function get(c::CondReduce)
  @assert myid() == 1
  if !isa(c.worksplit, NoSplit)
    for worker in workers()
      if worker == c.worksplit.worker
        continue
      else
        other = @fetchfrom worker Main.trs.postProcInstance
        merge(c, other)
      end
    end
  end

  globalmask = toMask(c.state)

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
    dataSnap = sort(collect(dataType, keys(c.traceIdx[k])))
    idxes = find(c.mask[k] & globalmask)
    sampleSnap = BitArray{2}(length(dataSnap), length(idxes))
    @printf("Reduction for %d: %d left after global dup col removal, %d left after sample reduction, %d left combined\n", k, countnz(globalmask), countnz(c.mask[k]), length(idxes))

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

# This pass will work on trs objects opened with trs = InspectorTrace("name.trs", true)
function tobits(x::Vector{UInt64})
  bits = length(x)*64

  # this is a fast hack to create BitVectors
  a = BitVector()
  a.chunks = x
  a.len = bits
  a.dims = (0,)

  return a
end

function tobits(x::Vector{UInt8})
  ret = falses(length(x)*8)
  for i in 1:length(x)
    for j in 1:8
      ret[(i-1)*8+j] = ((x[i] >> (j-1)) & 1) == 1
    end
  end
  return BitVector(ret)
end
