# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Authors: Cees-Bart Breunesse, Ilya Kizhvatov
# Implements technique described in "Behind the Scene of Side Channel Attacks", Asiacrypt 2013 (see docs/cond_avg.pdf)

export CondAvg

import Base.get,Base.show

mutable struct CondAvg <: Cond
  averages::Dict{Int,Dict}
  counters::Dict{Int,Dict}
  globcounter::Int

  function CondAvg()
    averages = Dict{Int,Dict}()
    counters = Dict{Int,Dict}()
    new(averages, counters, 0)
  end
end

show(io::IO, a::CondAvg) = print(io, "Cond avg")

function reset(c::CondAvg)
  c.averages = Dict{Int,Dict}()
  c.counters = Dict{Int,Dict}()
  c.globcounter = 0
end

function addAverage(c::CondAvg, samples::AbstractVector, average::Vector, counter::Int)

  for i in eachindex(samples)
    @inbounds average[i] += (samples[i] - average[i]) / counter
  end
end

# function add(c::CondAvg, trs::Traces, traceIdx::Int)
#   data = getData(trs, traceIdx)
#   if length(data) == 0
#     return
#   end

#   samples = getSamples(trs, traceIdx)
#   if length(samples) == 0
#     return
#   end

#   add(c,samples,data,traceIdx)

# end

function add(c::CondAvg, samples::AbstractVector{S}, data::AbstractVector{D}, traceIdx::Int) where {S,D}
  for idx in eachindex(data)
    val = data[idx]

    if !haskey(c.counters, idx)
     c.counters[idx] = Dict{D,Int}()
     c.averages[idx] = Dict{D,Vector{Float64}}()
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
  # @assert myid() == 1
  # if !ismissing(trs)
  #   ww = workers()
  #   for worker in ww
  #     if worker == ww[1]
  #       # skip this because we fetched this result into process 1 already
  #       continue
  #     else
  #       other = @fetchfrom worker meta(trs.trsfn()).postProcInstance
  #       merge(c, other)
  #     end
  #   end
  # end

  dataType = typeof(first(c.averages).second).parameters[1]

  nrPairs = length(keys(c.counters))
  datas = Vector{Vector{dataType}}(undef,nrPairs)
  averages = Vector{Matrix{Float64}}(undef,nrPairs)
  nrSamples = length(first(first(c.averages)[2])[2])

  for k in 1:nrPairs
    dataSnap = sort(collect(dataType, keys(c.counters[k])))
    # sampleSnap = Matrix{Float64}(undef,length(dataSnap), nrSamples)
    sampleSnap = zeros(Float64,length(dataSnap), nrSamples)
    for i in 1:length(dataSnap)
      sampleSnap[i,:] = c.averages[k][dataSnap[i]]
    end
    datas[k] = dataSnap
    averages[k] = sampleSnap
  end

  @printf("\nAveraged %d input traces into %d averages, %s data type, %s sample type\n", c.globcounter, length(keys(c.counters)), string(dataType), string(eltype(averages[1])))


  return (datas,averages)
end

getGlobCounter(c::CondAvg) = c.globcounter
getAverages(c::CondAvg) = c.averages
getCounters(c::CondAvg) = c.counters
