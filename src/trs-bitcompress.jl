# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Ruben Muijrers, Juliafied by Cees-Bart Breunesse

export BitCompress,bitcompress,toMask

mutable struct BitCompress
  tmp::Vector{Int}
  duplicates::Vector{Int}
  inverses::Vector{Int}
  first::Bool

  function BitCompress(nrOfSamples::Int)
    return new(Vector{Int}(undef,nrOfSamples), Vector{Int}(undef,nrOfSamples), Vector{Int}(undef,nrOfSamples), true)
  end
end

function reset!(c::BitCompress)
  fill!(c.tmp, 0)
  fill!(c.duplicates, 0)
  fill!(c.inverses, 0)
  c.first = true
end

function toMask(state::BitCompress)
  mask = BitVector(undef,length(state.duplicates))
  for (i,val) in enumerate(state.duplicates)
    mask[i] = (val == i) && (state.inverses[val] == i)
  end
  return mask
end

function stats(state::BitCompress) 
  keptnondups = 0
  keptnondupsandnoninvs = 0

  for (i,val) in enumerate(state.duplicates)
    if val == i
      keptnondups += 1
      if state.inverses[val] == i
        keptnondupsandnoninvs += 1
      end
    end
  end

  return (keptnondups, keptnondupsandnoninvs)

end

setInverses = (s,i,j) -> (i < j) ? s.inverses[j] = i : s.inverses[i] = j

# Efficient removal of duplicate columns and inverse duplicate columns for
# row-wise available data by Ruben Muijrers.
function bitcompress(state::BitCompress, input::AbstractArray)
  if state.first
    # state.duplicates[find(x -> x == input[1], input)] .= 1
    # state.duplicates[find(x -> x != input[1], input)] .= findfirst(x -> x != input[1], input)
    x = input[1]
    seen = false
    y = 0
    for b in eachindex(input)
      state.inverses[b] = b
      if input[b] == x
        state.duplicates[b] = 1
      else
        if !seen
           seen = true
           y = b
        end
        state.duplicates[b] = y
      end
    end

    if y != 0
      state.inverses[y] = 1
    end

    state.first = false
  else
    duplicates = state.duplicates
    tmp = state.tmp
    inverses = state.inverses

    @inbounds for (i,dupi) in enumerate(duplicates)
      # freshly made for keeping track of splits
      tmp[i] = i
      # if we were labeled a duplicate before
      if dupi != i
        #  check if we still belong to the same group
        if input[i] != input[dupi]
          # if not, check if we split this group earlier
          if tmp[dupi] == dupi
            # if not, make a new group
            tmp[dupi] = i
          end
          # assign the new group
          duplicates[i] = tmp[dupi]
        end
      end
    end

    @inbounds for (i,j) in enumerate(inverses)
      if j != i
        tmpj = tmp[j]
        tmpi = tmp[i] 
        # Ruben's Magic
        jHasNewGroup = (tmpj != j)
        iHasNewGroup = (tmpi != i)

        if input[i] == input[j]
          if jHasNewGroup
            setInverses(state, i, tmpj)
          end

          if iHasNewGroup
            setInverses(state, tmpi, j)
          end
          
          if inverses[i] == j
            inverses[i] = i
          end
        elseif jHasNewGroup && iHasNewGroup
          setInverses(state, tmpi, tmpj)
        end
      end
    end
  end
end

function bitcompress(m::BitArray{2})
  (rows,cols) = size(m)
  state = BitCompress(cols)
  for r in 1:rows
    bitcompress(state, m[r,:])
  end

  colstokeep = toMask(state)
  return m[:,colstokeep]
end
