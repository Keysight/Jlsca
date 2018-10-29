# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

module Align

using FFTW
using Statistics

include("align-static.jl")
include("align-fastdtw.jl")

end
