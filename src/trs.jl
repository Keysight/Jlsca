module Trs

using Distributed
using Printf

abstract type PostProcessor end

export init
init(::PostProcessor) = nothing

export PostProcessor
export getData,getSamples,writeData,writeSamples

include("conditional.jl")

include("trs-core.jl")
include("trs-distributed.jl")
include("trs-inspector.jl")
include("trs-splitbinary.jl")
include("trs-bitcompress.jl")
include("trs-virtuatrace.jl")
include("trs-secondorder.jl")

include("distributed.jl")
include("conditional-average.jl")
include("conditional-bitwisereduction.jl")
# include("incremental-correlation.jl")

include("trs-convert.jl")

end
