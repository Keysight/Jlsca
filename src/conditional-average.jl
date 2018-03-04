# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Authors: Cees-Bart Breunesse, Ilya Kizhvatov
# Implements technique described in "Behind the Scene of Side Channel Attacks", Asiacrypt 2013 (see docs/cond_avg.pdf)

export CondAvg

import Base.get,Base.show

type CondAvg <: Cond
  averages::Dict{Int,Dict{Int,Vector{Float64}}}
  counters::Dict{Int,Dict{Int,Int}}
  globcounter::Int
  worksplit::WorkSplit

  function CondAvg()
    CondAvg(NoSplit())
  end

  function CondAvg(worksplit::WorkSplit)
    averages = Dict{Int,Dict{Int,Vector{Float64}}}()
    counters = Dict{Int,Dict{Int,Int}}()
    # @printf("Conditional averaging, split %s\n", worksplit)

    new(averages, counters, 0, worksplit)
  end
end

show(io::IO, a::CondAvg) = print(io, "Cond avg")

function reset(c::CondAvg)
  c.averages = Dict{Int,Dict{Int,Vector{Float64}}}()
  c.counters = Dict{Int,Dict{Int,Int}}()
  c.globcounter = 0
end

function addAverage(c::CondAvg, samples::Vector, average::Vector, counter::Int)

  for i in eachindex(samples)
    @inbounds average[i] += (samples[i] - average[i]) / counter
  end
end

function add(c::CondAvg, trs::Trace, traceIdx::Int)
  data = getData(trs, traceIdx)
  if length(data) == 0
    return
  end

  samples = getSamples(trs, traceIdx)
  if length(samples) == 0
    return
  end

  add(c,samples,data,traceIdx)

end

function add(c::CondAvg, samples::Vector{S}, data::Vector{D}, traceIdx::Int) where {S,D}
  for idx in eachindex(data)
    val = data[idx]

    if !haskey(c.counters, idx)
     c.counters[idx] = Dict{Int,Int}()
     c.averages[idx] = Dict{Int,Vector{Float64}}()
    end

    if !haskey(c.counters[idx], val)
     c.counters[idx][val] = 0
     c.averages[idx][val] = zeros(Float64, length(samples))
    end

    c.counters[idx][val] += 1
    counter = c.counters[idx][val]
    average = c.averages[idx][val]
    addAverage(c, samples, average, counter)
  end

  c.globcounter += 1

end

function merge(this::CondAvg, other::CondAvg)
  this.globcounter += other.globcounter
  for (idx,dictofavgs) in other.averages
    if !haskey(this.averages, idx)
      this.averages[idx] = dictofavgs
    else
      for (val, avg) in dictofavgs
        if val in keys(this.averages[idx])
          delta = other.averages[idx][val] - this.averages[idx][val]
          n = other.counters[idx][val] + this.counters[idx][val]
          this.averages[idx][val] += other.counters[idx][val] .* delta ./ n
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
          this.counters[idx][val] += count
        else
          this.counters[idx][val] = count
        end
      end
    end
  end

end

function get(c::CondAvg)
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

  datas = Array[]
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
    throw(ErrorException("Unsupported and not recommended ;)"))
  end

  for k in sort(collect(keys(c.counters)))
    dataSnap = sort(collect(dataType, keys(c.counters[k])))
    sampleSnap = Matrix{Float64}(length(dataSnap), length(first(first(c.averages)[2])[2]))
    for i in 1:length(dataSnap)
      sampleSnap[i,:] = c.averages[k][dataSnap[i]]
    end
    push!(datas, dataSnap)
    push!(averages, sampleSnap)
  end

  @printf("\nAveraged %d input traces into %d averages, %s data type, %s sample type\n", c.globcounter, length(keys(c.counters)), string(dataType), string(eltype(averages[1])))


  return (datas,averages)
end

getGlobCounter(c::CondAvg) = c.globcounter
getAverages(c::CondAvg) = c.averages
getCounters(c::CondAvg) = c.counters
