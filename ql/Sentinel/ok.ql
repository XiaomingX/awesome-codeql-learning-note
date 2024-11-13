/**
 * @kind path-problem
 */

import java;
import semmle.code.java.dataflow.TaintTracking;
import semmle.code.java.dataflow.FlowSources;
import DataFlow::PathGraph;

/**
 * 将添加机器到定时任务执行链中
 * 该谓词用于查找 addMachine 和 fetchOnce 之间的调用关系
 */
predicate machine(DataFlow::Node expSrc, DataFlow::Node expDest) {
  exists(MethodAccess ma, Method me, MethodAccess ma1, Method me1 |
      me.getName() = "addMachine" and
      me = ma.getMethod() and 
      expSrc.asExpr() = ma.getAnArgument() and
      me1.getName() = "fetchOnce" and 
      ma1.getMethod() = me1 and 
      ma1.getAnArgument() = expDest.asExpr()
  )
}

/**
 * 将添加机器到每个 MachineInfo 调用自身方法
 * 该谓词用于查找 addMachine 和 MachineInfo 中 get 方法之间的调用关系
 */
predicate machine1(DataFlow::Node expSrc, DataFlow::Node expDest) {
  exists(MethodAccess ma, Method me, MethodAccess ma1, Method me1 |
      me.getName() = "addMachine" and
      me = ma.getMethod() and 
      expSrc.asExpr() = ma.getAnArgument() and    
      me1.getQualifiedName().matches("%MachineInfo%") and 
      me1.getName().matches("%get%") and
      ma1.getMethod() = me1 and 
      expDest.asExpr() = ma1
  )
}

/**
 * 将机器获取过程连接到 MachineInfo 的 get 方法
 * 该谓词用于查找 getMachines 和 MachineInfo 中 get 方法之间的调用关系
 */
predicate machine2(DataFlow::Node expSrc, DataFlow::Node expDest) {
  exists(MethodAccess ma, Method me, MethodAccess ma1, Method me1 |
      me.getName() = "getMachines" and
      me = ma.getMethod() and 
      expSrc.asExpr() = ma and
      me1.getQualifiedName().matches("%MachineInfo%") and 
      me1.getName().matches("%get%") and
      ma1.getMethod() = me1 and 
      expDest.asExpr() = ma1
  )
}

/**
 * SsrfConfig 类继承 TaintTracking::Configuration，用于定义源和汇
 */
class SsrfConfig extends TaintTracking::Configuration {
  SsrfConfig() { this = "SsrfConfig" }

  // 定义数据流的源节点
  override predicate isSource(DataFlow::Node src) { 
    src instanceof RemoteFlowSource
  }

  // 定义数据流的汇节点
  override predicate isSink(DataFlow::Node sink) {
    exists(ConstructorCall call, Class clz |
      call.getAnArgument() = sink.asExpr() and 
      call.getConstructedType() = clz and 
      clz.getName() = "HttpGet"
    )
  }

  // 定义附加的数据流步骤
  override predicate isAdditionalTaintStep(DataFlow::Node expSrc, DataFlow::Node expDest) {
    exists(MethodAccess ma, Method me, MethodAccess maa, Method mee |
      me.getName() = "setIp" and
      ma.getMethod() = me and 
      expSrc.asExpr() = ma.getAnArgument() and
      mee.getName().matches("getIp") and
      maa.getMethod() = mee and 
      expDest.asExpr() = maa 
    )
  }
}

// 查找从源到汇的完整路径
from SsrfConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select source.getNode(), source, sink, "source"
