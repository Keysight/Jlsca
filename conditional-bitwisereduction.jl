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
export CondReduce

using ProgressMeter

type CondReduce <: Cond
  indexes::Vector{Vector{Int}}
  mask::Vector{BitVector}
  counters::Array{Int,2}
  globcounter::Int
  trs::Trace

  function CondReduce(dataColumns, sampleLength, nrOfAverages, trs::Trace)
    # a vector of vectors with vectors is fugly but much faster than a Matrix because these vectors are independent
    indexes = Vector{Vector{Int}}(dataColumns)
    mask = Vector{BitVector}(dataColumns)
    for i in 1:dataColumns
        indexes[i] = Vector{Int}(nrOfAverages)
        mask[i] = trues(sampleLength)
    end
    counters = zeros(Int, (dataColumns, nrOfAverages))

    @printf("Conditional bit reduction for max %d averages of %d samples per data offset\n", nrOfAverages, sampleLength)
    new(indexes, mask, counters, 0, trs)
  end
end


# only works on samples of BitVector type, do addSamplePass(trs, tobits)
# to create this input efficiently!
function add(c::CondReduce, datav::Vector, sample::BitVector, idx::Int)
  for d in eachindex(datav)
      data = datav[d]

      if c.counters[d, data+1] == 0
        c.indexes[d][data + 1] = idx
        c.counters[d, data+1] = 1
      else
        c.counters[d, data+1] += 1
        currmask = c.mask[d]
        idxes = find(currmask)
        maskidxes = idxes[find(c.trs[c.indexes[d][data + 1]][2][idxes] $ sample[idxes])]
        currmask[maskidxes] .= false
      end
  end

  c.globcounter += 1
end

function get(c::CondReduce)
  datas = Matrix[]
  reducedsamples = Matrix[]

  if size(c.counters)[2] <= 2^8
    dataType = UInt8
  elseif size(c.counters)[2] <= 2^16
    dataType = UInt16
  else
    throw(Exception("Unsupported and not recommended ;)"))
  end

  for i in 1:size(c.counters)[1]
    dataSnap = find(c.counters[i,:])
    idxes = find(c.mask[i])
    @printf("input %d: #columns from %d -> %d after conditional bitwise reduction\n", i, length(c.mask[i]), length(idxes))
    sampleSnap = BitArray{2}(length(dataSnap), length(idxes))
    for j in 1:length(dataSnap)
        sampleSnap[j,:] = c.trs[c.indexes[i][dataSnap[j]]][2][idxes]
    end
    dataSnap = dataSnap .- 1
    dataSnap = reshape(convert(Array{dataType,1}, dataSnap), length(dataSnap),1)
    push!(datas, dataSnap)
    push!(reducedsamples, sampleSnap)
    @printf("\n")
  end

  @printf("\nReduced %d input traces, %s data type\n", c.globcounter, string(dataType))

  return (datas,reducedsamples)
end

function getCounter(c::CondReduce)
  return c.globcounter
end
