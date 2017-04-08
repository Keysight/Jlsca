# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Ruben Muijrers, Juliafied by Cees-Bart Breunesse

export BitCompress,bitcompress,tobits,toMask

type BitCompress
  tmp::Vector{Int}
  duplicates::Vector{Int}
  inverses::Vector{Int}
  first::Bool

  function BitCompress(nrOfSamples::Int)
    return new(Vector{Int}(nrOfSamples), Vector{Int}(nrOfSamples), Vector{Int}(nrOfSamples), true)
  end
end

function toMask(state::BitCompress)
  mask = BitVector(length(state.duplicates))
  for i in 1:length(state.duplicates)
    mask[i] = (state.duplicates[i] == i) && (state.inverses[i] == i)
  end
  return mask
end

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

    state.inverses[y] = 1

    state.first = false
  else
    duplicates = state.duplicates
    tmp = state.tmp
    inverses = state.inverses

    @inbounds for i in 1:length(duplicates)
      # freshly made for keeping track of splits
      tmp[i] = i
      # if we were labeled a duplicate before
      if duplicates[i] != i
        #  check if we still belong to the same group
        if input[i] != input[duplicates[i]]
          # if not, check if we split this group earlier
          if tmp[duplicates[i]] == duplicates[i]
            # if not, make a new group
            tmp[duplicates[i]] = i
          end
          # assign the new group
          duplicates[i] = tmp[duplicates[i]]
        end
      end
    end

    @inbounds for i in 1:length(inverses)
      if inverses[i] != i
        # Ruben's Magic
        j = inverses[i]
        jHasNewGroup = (tmp[j] != j)
        iHasNewGroup = (tmp[i] != i)
        setInverses = (i,j) -> (i < j) ? inverses[j] = i : inverses[i] = j

        if input[i] == input[j]
          if jHasNewGroup
            setInverses(i, tmp[j])
          end

          if iHasNewGroup
            setInverses(tmp[i], j)
          end
          
          if inverses[i] == j
            inverses[i] = i
          end
        elseif jHasNewGroup && iHasNewGroup
          setInverses(tmp[i], tmp[j])
        end
      end
    end
  end
end
