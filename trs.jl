module Trs

include("conditional.jl")

include("trs-core.jl")
include("trs-distributed.jl")
include("trs-inspector.jl")
include("trs-inspector-mmap.jl")
include("trs-splitbinary.jl")

include("conditional-distributed.jl")
include("conditional-average.jl")
include("conditional-bitwisereduction.jl")

end
