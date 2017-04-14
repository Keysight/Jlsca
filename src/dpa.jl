# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Authors: Cees-Bart Breunesse, Ilya Kizhvatov

module Dpa
export dpa

import Base.cor

using ProgressMeter


# Vanilla DPA on data and sample matrices.
function dpa(data::AbstractArray, samples::AbstractArray, keyByteOffsets::Vector{Int}, intermediateFun::Function, leakageFuns::Vector{Function}, statistic=cor, kcVals=collect(UInt8, 0:255), H_type=UInt8, HL_type=UInt8)
  (tr,tc) = size(samples)
  (dr,dc) = size(data)
  nrKcVals = length(kcVals)

  tr == dr || throw(DimensionMismatch())
  dc == length(keyByteOffsets) || throw(DimensionMismatch())

  # temp storage for hypothetical intermediates for a single data column
  H = zeros(H_type, dr, nrKcVals)

  # hypothetical leakages for all leakageFuns for each intermediate for each data column.
  HL = zeros(HL_type, dr, nrKcVals*dc*length(leakageFuns))

  # progress counter kicks in when our hyp calc is really slow
  m = Progress(dc, 1)

  # group all hypothetical leakages together for a single data column/key chunk offset, this makes summing correlation values for a single key chunk candidate later much easier. Order is: HL0(H(0)) | HL1(H(0)) .. | HLn(H(0)) | HL0(H(1)) | HL1(H(1)) ..
  for j in 1:dc
    # for a given data column, compute the hypothetical intermediate for each key hypothesis. Overwritten the next iteration.
    for i in kcVals
      H[:,i+1] = intermediateFun(data[:,j], keyByteOffsets[j], i)
    end
    # for a given data column, compute all the leakages for all hypothetical intermediates for each key hypothesis and append to the large HL matrix
    for l in 1:length(leakageFuns)
      hl_lower = (j-1)*nrKcVals*length(leakageFuns) + (l-1)*nrKcVals + 1
      hl_upper = hl_lower + nrKcVals - 1
      HL[:,hl_lower:hl_upper] = leakageFuns[l](H)
    end
    next!(m)
  end

  # columnwise correlate/difference of means/mia the hypothetical leakages with samples
  C = statistic(samples, HL)

  return C
end

end
