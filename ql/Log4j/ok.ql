# Datagear 漏洞与 CodeQL 分析实现详解

在学习 **CodeQL** 的过程中，偶然发现了 [Datagear](https://github.com/datageartech/datagear) 这个项目，觉得可能存在一些简单漏洞。本文详细讲解如何挖掘任意文件读取漏洞，并结合 CodeQL 进行实现分析。

之前有幸在 [safe6sec](https://github.com/safe6Sec) 师傅的帮助下完成过类似的任务，非常感谢！以下内容详细记录了利用 CodeQL 进行漏洞分析的全过程。

---

## 1. 什么是任意文件读取漏洞？

任意文件读取漏洞是一种高危安全漏洞，攻击者可以通过恶意构造输入参数读取服务器上的任意文件，包括配置文件、敏感数据等。常见成因：
1. 文件路径未被有效过滤或验证；
2. 路径遍历（Path Traversal）漏洞未处理。

---

## 2. 漏洞复现：Datagear 任意文件读取

在项目代码中，可以通过以下方式触发漏洞：

### 代码分析
```java
IOUtil.write(tempFile, out);
```

其中：
- **`tempFile`** 是从外部输入传递的文件路径；
- 若未进行路径验证，攻击者可以通过路径遍历控制 **`tempFile`**，导致读取任意文件。

### 演示截图

**漏洞触发**
![漏洞示例](https://user-images.githubusercontent.com/63966847/148550868-25b09ed1-a3f9-4cd9-b473-bdd014450bd0.png)

**读取敏感文件**
![读取文件结果](https://user-images.githubusercontent.com/63966847/148550881-98915067-f875-44a3-92fd-3f31450045d5.png)

---

## 3. CodeQL 漏洞分析与实现

**CodeQL** 是 GitHub 提供的一种静态分析语言，广泛应用于代码漏洞挖掘。

### 基础知识

**数据流分析概念：**
- **Source（源点）：** 用户输入或未信任的外部数据；
- **Sink（汇点）：** 最终导致漏洞的敏感操作（如写文件、执行命令等）；
- **Sanitizer（清理器）：** 用于过滤或验证数据的操作，避免恶意输入到达敏感点。

### 初步实现：Source 和 Sink 定义

#### 定义 Source（数据流起点）
我们可以利用 CodeQL 默认的 **`RemoteFlowSource`** 类来定义常见的输入点，比如 Spring Boot 的 `@RequestMapping` 参数。
```java
override predicate isSource(DataFlow::Node src) {
    src instanceof RemoteFlowSource // 默认实现
}
```

#### 定义 Sink（敏感操作点）
漏洞关键点是 **`IOUtil.write`** 方法，其第一个参数 **`tempFile`** 为潜在污染点：
```java
override predicate isSink(DataFlow::Node sink) {
    exists(Method method, MethodAccess call |
        method.hasName("write")
        and call.getMethod() = method
        and sink.asExpr() = call.getArgument(0) // 第一个参数
    )
}
```

### 初步结果
执行以上代码后，发现了 **163** 个潜在漏洞点，但误报较多。需要进一步优化。

---

## 4. 优化漏洞检测规则

### 优化 Sink 点（特定方法限定）

进一步分析代码发现，并非所有 **`write`** 方法都存在漏洞。例如，以下方法是目标：
```java
public static void write(File file, OutputStream out)
```

我们限定 `write` 方法的声明位置：
```java
override predicate isSink(DataFlow::Node sink) {
    exists(Method method, MethodAccess call |
        method.hasName("write")
        and call.getMethod() = method
        and method.getDeclaringType().getAnAncestor().hasQualifiedName("org.datagear.util", "IOUtil")
        and call.getArgument(0).getType().hasName("File") // 文件类型
        and sink.asExpr() = call.getArgument(0)
    )
}
```

优化后结果从 **163** 减少到 **9**。

---

### 清理误报（Sanitizer）

分析结果中，部分输入点调用了 **`getOriginalFilename()`** 方法，该方法会清理路径穿越风险。我们使用 **Sanitizer** 消除误报：
```java
override predicate isSanitizer(DataFlow::Node node) {
    exists(MethodAccess call, Method method |
        method.hasName("getOriginalFilename")
        and call.getMethod() = method
        and call.getAChildExpr() = node.asExpr()
    )
}
```

---

### 自定义 Source 点（Spring Controller 输入）

部分结果并非路由输入导致，需要自定义 Source 点。定义 Spring Boot 的 Controller 参数为输入源：
```java
class ControllerAnno extends Annotation {
    ControllerAnno() {
        this.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestMapping") or
        this.getType().hasQualifiedName("org.springframework.web.bind.annotation", "GetMapping")
    }
}
private class SpringBootSource extends RemoteFlowSource {
    SpringBootSource() {
        this.asParameter().getCallable().getAnAnnotation() instanceof ControllerAnno
    }
    override string getSourceType() { result = "SpringBoot input parameter" }
}
```

---

### 最终实现：完整的 CodeQL 配置

```java
/**
 * @id datagear
 * @name Readfile
 * @description Arbitrary file read
 * @kind path-problem
 * @precision high
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import DataFlow::PathGraph

class ControllerAnno extends Annotation {
    ControllerAnno() {
        this.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestMapping") or
        this.getType().hasQualifiedName("org.springframework.web.bind.annotation", "GetMapping")
    }
}
private class SpringBootSource extends RemoteFlowSource {
    SpringBootSource() {
        this.asParameter().getCallable().getAnAnnotation() instanceof ControllerAnno
    }
    override string getSourceType() { result = "SpringBoot input parameter" }
}

class ReadfileConfig extends TaintTracking::Configuration {
    ReadfileConfig() { this = "ReadfileConfig" }

    override predicate isSource(DataFlow::Node src) { 
        src instanceof SpringBootSource
    }

    override predicate isSink(DataFlow::Node sink) {
        exists(Method method, MethodAccess call |
            method.hasName("write")
            and call.getMethod() = method
            and method.getDeclaringType().getAnAncestor().hasQualifiedName("org.datagear.util", "IOUtil")
            and call.getArgument(0).getType().hasName("File")
            and sink.asExpr() = call.getArgument(0)
        )
    }

    override predicate isSanitizer(DataFlow::Node node) {
        exists(MethodAccess call, Method method |
            method.hasName("getOriginalFilename")
            and call.getMethod() = method
            and call.getAChildExpr() = node.asExpr()
        )
    }
}

from ReadfileConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select source.getNode(), source, sink, "Potential file read vulnerability"
```

---

## 5. 结果分析

最终检测到 **9** 个漏洞点，成功验证存在任意文件读取漏洞。

**漏洞结果截图：**
![最终结果](https://user-images.githubusercontent.com/63966847/148550942-f916780f-24c8-4015-b12c-eaf6494e7d36.png)

---

## 6. 总结

通过对 **Datagear** 项目的漏洞挖掘，展示了 **CodeQL** 的强大能力。从初步规则设计到逐步优化分析，最终完成了高效的漏洞检测，实现关键点：
1. **精准定义 Source 和 Sink；**
2. **结合业务逻辑清理误报；**
3. **灵活使用 CodeQL 扩展类和规则。**

以上方法适用于任意文件读取、SQL 注入等多种漏洞场景。希望对你的漏洞挖掘工作有所启发！