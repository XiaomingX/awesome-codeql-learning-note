/**
 * @name Tainttrack Context lookup
 * @description 这段代码源自 https://mp.weixin.qq.com/s/JYco8DysQNszMohH6zJEGw
 * @kind 路径问题
 */

import java;
import semmle.code.java.dataflow.FlowSources;
import DataFlow::PathGraph;

// 代表从不同包中使用的各种Context类用于JNDI查找的情况
class Context extends RefType {
  Context() {
    // 检测不同的Context类型
    this.hasQualifiedName("javax.naming", "Context")
    or this.hasQualifiedName("javax.naming", "InitialContext")
    or this.hasQualifiedName("org.springframework.jndi", "JndiCallback")
    or this.hasQualifiedName("org.springframework.jndi", "JndiTemplate")
    or this.hasQualifiedName("org.springframework.jndi", "JndiLocatorDelegate")
    or this.hasQualifiedName("org.apache.shiro.jndi", "JndiCallback")
    or this.getQualifiedName().matches("%JndiCallback")
    or this.getQualifiedName().matches("%JndiLocatorDelegate")
    or this.getQualifiedName().matches("%JndiTemplate");
  }
}

// 代表用于追踪日志相关操作的Logger类
class Logger extends RefType {
  Logger() {
    this.hasQualifiedName("org.apache.logging.log4j.spi", "AbstractLogger");
  }
}

// 代表可能接收不信任输入的日志方法
class LoggerInput extends Method {
  LoggerInput() {
    this.getDeclaringType() instanceof Logger
    and this.hasName("error")
    and this.getNumberOfParameters() = 1;
  }

  // 获取error方法的第一个参数，这个参数被认为不信任
  Parameter getAnUntrustedParameter() {
    result = this.getParameter(0);
  }
}

// 判断表达式是否在JNDI查找中使用
predicate isLookup(Expr arg) {
  exists(MethodAccess ma |
    ma.getMethod().getName() = "lookup"
    and ma.getMethod().getDeclaringType() instanceof Context
    and arg = ma.getArgument(0)
  );
}

// 配置用于追踪查找操作中的污染流
class TainttrackLookup extends TaintTracking::Configuration {
  TainttrackLookup() {
    this = "TainttrackLookup";
  }

  // 指定污染的源，这里是LoggerInput中的不信任参数
  override predicate isSource(DataFlow::Node source) {
    exists(LoggerInput LoggerMethod |
      source.asParameter() = LoggerMethod.getAnUntrustedParameter()
    );
  }

  // 定义流过程中节点之间的额外污染步骤
  override predicate isAdditionalTaintStep(DataFlow::Node fromNode, DataFlow::Node toNode) {
    exists(MethodAccess ma, MethodAccess ma2 |
      ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.logging.log4j.core.impl", "ReusableLogEventFactory")
      and ma.getMethod().hasName("createEvent")
      and fromNode.asExpr() = ma.getArgument(5)
      and ma2.getMethod().getDeclaringType().hasQualifiedName("org.apache.logging.log4j.core.config", "LoggerConfig")
      and ma2.getMethod().hasName("log")
      and ma2.getMethod().getNumberOfParameters() = 2
      and toNode.asExpr() = ma2.getArgument(0)
    );
  }

  // 指定污染的污染下源，即在JNDI查找中使用的参数
  override predicate isSink(DataFlow::Node sink) {
    exists(Expr arg |
      isLookup(arg)
      and sink.asExpr() = arg
    );
  }
}

// 主查询，用于查找从源到污染池的污染路径
from TainttrackLookup config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "不安全的查找", source.getNode(), "这是用户输入";