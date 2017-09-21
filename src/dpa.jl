# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Authors: Cees-Bart Breunesse, Ilya Kizhvatov

export predict

using ProgressMeter


# DPA prediction
function predict(data::AbstractArray{In,1}, t::Target{In,Out}, kcVals::Vector{UInt8}, leakages::Vector{Leakage}) where {In,Out}
  (dr,) = size(data)
  nrKcVals = length(kcVals)
  nrLeakages = length(leakages)

  # temp storage for hypothetical intermediates for a single data column
  H = zeros(Out, dr, nrKcVals)

  # hypothetical leakages for all leakages for each intermediate for each data column.
  HL = zeros(UInt8, dr, nrKcVals*nrLeakages)

  j = 1
  # for a given data column, compute the hypothetical intermediate for each key hypothesis. Overwritten the next iteration.
  for i in kcVals
    for r in 1:dr
      H[r,i+1] = target(t, data[r,j], i)
    end
  end
  
  # for a given data column, compute all the leakages for all hypothetical intermediates for each key hypothesis and append to the large HL matrix
  for l in 1:nrLeakages
    hl_lower = (l-1)*nrKcVals + 1
    hl_upper = hl_lower + nrKcVals - 1
    for c in 1:nrKcVals
      for r in 1:dr
       HL[r,hl_lower+c-1] = leak(leakages[l], H[r,c])
      end
    end
  end

  return HL
end
