module Mia
export mia

using ProgressMeter

function mia(X::Vector, Y::Vector, normalized=false, base=2)
    numobs = length(X)
    if numobs != length(Y)
        @printf("Not matching length, X %d, Y %d\n" , length(X), length(Y))
        return Union
    end
    mutual_info = 0.0
    uniq_x = unique(X)
    uniq_y = unique(Y)
    for x in uniq_x
        wherex = find(xi->xi == x, X)
        px = length(wherex) / numobs
        for y in uniq_y
            wherey = find(yi->yi == y, Y)
            py = length(wherey) / numobs
            wherexy = intersect(wherex, wherey)
            pxy = length(wherexy) / numobs
            if pxy > 0
                # @printf("px: %s\n", px)
                # @printf("py: %s\n", py)
                # @printf("pxy: %s\n", pxy)
                # @printf("mia: %s\n", string((pxy / (px * py))))
                mutual_info += pxy * log(base, (pxy / (px * py)))
            end
        end
    end
    if normalized
        mutual_info = mutual_info / log2(numobs)
    end
    return mutual_info

end

function mia(O::Matrix, P::Matrix)
    (ro,co) = size(O)
    (rp,cp) = size(P)

    C = zeros(Float64, co, cp)

    progress = Progress(co*cp,1)

    for o in 1:co
        for p in 1:cp
            C[o,p] = mia(O[:,o], P[:,p])
            next!(progress)
        end
    end

    return C
end


end
