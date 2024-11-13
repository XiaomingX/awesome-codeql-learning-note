import go
import DataFlow::PathGraph

/**
 * 代表一个源节点，用于追踪目的。
 */
class GfSource1 extends DataFlow::Node {
    GfSource1() {
        exists(Function fun, CallExpr call, SelectorExpr se |
            // 此函数的命名应该为 RouteRegister 中的调用子以下一种方法：
            call.getTarget().hasQualifiedName(
                "github.com/grafana/grafana/pkg/api/routing.RouteRegister",
                ["Get", "Post", "Delete", "Put", "Patch", "Any"]
            ) and
            // 从 call 中获取对应参数，求应为 SelectorExpr 或者类参
            (call.getAnArgument() = se or call.getAnArgument().getAChildExpr() = se) and
            // 函数的参照返回应该是 se
            fun.getAReference() = se.getSelector() and
            // 使用的参数为本调用的参数
            fun.getAParameter() = this.asParameter()
        )
    }
}

/**
 * 判断数据流是否从 expSrc 进入 expDest
 */
predicate isOther(DataFlow::Node expSrc, DataFlow::Node expDest) {
    exists(CallExpr call, SimpleAssignStmt sas |
        // call的target为“Params”并匹配对应的过程
        call.getTarget().getName().toString() = "Params" and
        call.getArgument(0) = expSrc.asExpr() and
        // 判断子数的为Parent的第一个child，并和expDest的Expr位置匹配
        sas.getRhs().getAChild() = call.getParent*().getAChild() and
        sas.getRhs() = expDest.asExpr()
    )
}

/**
 * 用于追踪源和收集器设置的配置类
 */
class Gfconfig extends TaintTracking::Configuration {
    Gfconfig() {
        this = "Gfconfig"
    }

    /**
     * 判断给定节点是否为带污源。
     */
    override predicate isSource(DataFlow::Node source) {
        source instanceof GfSource1
    }

    /**
     * 判断给定节点是否为污点。
     */
    override predicate isSink(DataFlow::Node sink) {
        exists(Function fun, CallExpr call |
            // 此函数使用应为 "os" 包中的 Open 
            fun.hasQualifiedName("os", "Open") and
            call.getTarget() = fun and
            call.getAnArgument() = sink.asExpr()
        )
    }

    /**
     * 判断在 expSrc 和 expDest 之间是否存在进一步的带污流步骤。
     *
     * 注意：污点只能含有两个参数，并第二个作为应为的收集器。
     */
    override predicate isAdditionalTaintStep(DataFlow::Node expSrc, DataFlow::Node expDest) {
        isOther(expSrc, expDest)
    }
}

/**
 * 追溯使用 Gfconfig 配置的污点路径。
 */
from Gfconfig gf, DataFlow::PathNode source, DataFlow::PathNode sink
where gf.hasFlowPath(source, sink)
select source.getNode(), source, sink, "test"