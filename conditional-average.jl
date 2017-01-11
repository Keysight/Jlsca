# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Authors: Cees-Bart Breunesse, Ilya Kizhvatov
# Implements technique described in "Behind the Scene of Side Channel Attacks", Asiacrypt 2013 (see docs/cond_avg.pdf)

export CondAvg

import Base.get

type CondAvg <: Cond
  averages::Dict{Int,Dict{Int,Vector{Float64}}}
  counters::Dict{Int,Dict{Int,Int}}
  globcounter::Int
  numberOfAverages::Int
  numberOfCandidates::Int
  worksplit::WorkSplit
  range::Range

  function CondAvg(numberOfAverages::Int, numberOfCandidates::Int)
    averages = Dict{Int,Dict{Int,Vector{Float64}}}()
    counters = Dict{Int,Dict{Int,Int}}()
    worksplit = WorkSplit(numberOfAverages, numberOfCandidates)
    range = getWorkerRange(worksplit)
    @printf("Conditional averaging, handling data range %s\n", range)

    new(averages, counters, 0, numberOfAverages, numberOfCandidates, worksplit, range)
  end
end

function addAverage(c::CondAvg, idx::Int, val::Int, samples::AbstractVector)
  c.counters[idx][val] += 1
  counter::Int = c.counters[idx][val]
  average::Vector{Float64} = c.averages[idx][val]

  for i in eachindex(samples)
    @inbounds average[i] += (samples[i] - average[i]) / counter
  end
end

function add(c::CondAvg, trs::Trace, traceIdx::Int)
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

    if !haskey(c.counters, idx)
     c.counters[idx] = Dict{Int,Int}()
     c.averages[idx] = Dict{Int,Vector{Float64}}()
    end

    if !haskey(c.counters[idx], val)
     c.counters[idx][val] = 0
     c.averages[idx][val] = zeros(Float64, length(get(samples)))
    end

    addAverage(c, idx, Int(val), get(samples))

  end

  c.globcounter += 1

end

function merge(this::CondAvg, other::CondAvg)
  for (idx,dictofavgs) in other.averages
    if !haskey(this.averages, idx)
      this.averages[idx] = dictofavgs
    else
      for (val, avg) in dictofavgs
        if val in keys(this.averages[idx])
          throw(ErrorException("fixme"))
        else
          this.averages[idx][val] = avg
        end
      end
    end
  end

  for (idx,dictofcounts) in other.counters
    if !haskey(this.counters, idx)
      this.counters[idx] = dictofcounts
    else
      for (val, count) in dictofcounts
        if val in keys(this.counters[idx])
          throw(ErrorException("fixme"))
        else
          this.counters[idx][val] = count
        end
      end
    end
  end

end

function get(c::CondAvg)
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
  averages = Matrix[]

  maxVal = 0
  for k in keys(c.counters)
    maxVal = max(maxVal, findmax(keys(c.counters[k]))[1])
  end

  if maxVal <= 2^8
    dataType = UInt8
  elseif maxVal <= 2^16
    dataType = UInt16
  else
    throw(Exception("Unsupported and not recommended ;)"))
  end

  for k in sort(collect(keys(c.counters)))
    dataSnap = collect(dataType, keys(c.counters[k]))
    sampleSnap = Matrix{Float64}(length(dataSnap), length(first(first(c.averages)[2])[2]))
    for i in 1:length(dataSnap)
      sampleSnap[i,:] = c.averages[k][dataSnap[i]]
    end
    dataSnap = reshape(convert(Array{dataType,1}, dataSnap), length(dataSnap),1)
    push!(datas, dataSnap)
    push!(averages, sampleSnap)
  end

  @printf("\nAveraged %d input traces, %s data type, %s sample type\n", c.globcounter, string(dataType), string(eltype(averages[1])))


  return (datas,averages)
end

getGlobCounter(c::CondAvg) = c.globcounter
getAverages(c::CondAvg) = c.averages
getCounters(c::CondAvg) = c.counters
