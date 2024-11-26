# CodeQL 学习记录

## 学习心得

1. **基础知识**  
   CodeQL 的强大在于其数据流分析和污点跟踪功能，这对于漏洞挖掘非常实用。

2. **案例实践**  
   实践中，通过分析真实漏洞案例（如 Log4j、Fastjson 等），可以更深入理解 CodeQL 的使用场景和方法。

3. **进阶技能**  
   熟悉规则编写和分析流程后，可以尝试自定义复杂的规则，如 `RemoteFlowSource` 的定义。

## 下一步计划

- 阅读未完成的学习资料。  
- 尝试在 Go 和 Java 项目中更多应用 CodeQL。  
- 学习规则编写的进阶方法，并优化现有的分析能力。

### 下载资源和工具

1. **官方文档**： [CodeQL 文档](https://codeql.github.com/docs/codeql-cli/)  
2. **命令行工具**： [CodeQL CLI 二进制文件](https://github.com/github/codeql-cli-binaries)  
3. **示例项目**： [VSCode CodeQL Starter](https://github.com/github/vscode-codeql-starter)  
4. **数据库与查询工具**： [LGTM 平台](https://lgtm.com/) （支持在线查询和规则搜索）

---

### 生成数据库的步骤

#### 1. 创建索引数据库

在运行查询之前，必须先生成代码的索引数据库：

```bash
codeql database create <数据库名> --language=<语言标识符>
```

支持的语言及其对应的标识符：

| 编程语言             | 标识符       |
| ------------------- | ---------- |
| C/C++              | cpp        |
| C#                 | csharp     |
| Go                 | go         |
| Java               | java       |
| JavaScript/TypeScript | javascript |
| Python             | python     |
| Ruby               | ruby       |

#### 示例：创建 Java 代码扫描数据库

```bash
codeql database create D:\codeqldb/javasec \
  --language=java \
  --command="mvn clean install --file pom.xml -Dmaven.test.skip=true" \
  --source-root=./javasec
```

- **`--source-root`**：源码路径，默认是当前目录（可省略）。  
- **`--command`**：用于构建项目的命令。  

##### 常见构建命令

- **跳过测试并构建**：  
  ```bash
  --command="mvn clean install --file pom.xml -Dmaven.test.skip=true"
  ```
- **忽略构建失败**：  
  ```bash
  --command="mvn -fn clean install --file pom.xml -Dmaven.test.skip=true"
  ```

##### 包含 XML 文件的特殊处理

如需将 `.xml` 文件包含在 CodeQL 数据库中，可以拆分命令如下：

```bash
codeql database init --source-root=<源码路径> --language=java <数据库名>
codeql database trace-command --working-dir=<源码路径> <数据库名> <Java 构建命令>
codeql database index-files --language=xml --include-extension=.xml --working-dir=<源码路径> <数据库名>
codeql database finalize <数据库名>
```

或者在 `codeql-cli/java/tools/pre-finalize.cmd` 文件中插入以下内容：

```bash
--include "**/resources/**/*.xml"
```

---

#### 2. 更新数据库

如果需要更新已有的数据库：

```bash
codeql database upgrade <数据库路径>
```

更多详情参考：[CodeQL 官方指南](https://help.semmle.com/lgtm-enterprise/admin/help/prepare-database-upload.html)

---

### 编译型语言与非编译型语言

- **编译型语言**（如 Java）：需要在生成数据库时包含项目的编译步骤。  
- **非编译型语言**（如 JavaScript、Python）：直接扫描代码即可。  
- **Go 语言**：既可编译，也可直接扫描。


# 简化后的描述

## 基础查询

### 按方法名称查询

1. 查询名称为 `toObject` 的方法：
   ```java
   import java

   from Method method
   where method.hasName("toObject")
   select method
   ```

2. 查询方法及其所属的类名：
   ```java
   import java

   from Method method
   where method.hasName("toObject")
   select method, method.getDeclaringType()
   ```

### 按方法名称和接口查询

例如，查找 `ContentTypeHandler` 所有子类的 `toObject` 方法：
```java
import java

from Method method
where method.hasName("toObject") and 
      method.getDeclaringType().getASupertype().hasQualifiedName("org.apache.struts2.rest.handler", "ContentTypeHandler")
select method
```

### Call 与 Callable

- **Callable**：表示方法或构造器的集合。
- **Call**：表示调用 Callable 的过程（例如方法调用、构造器调用）。

#### 过滤方法调用

查找 `ContentTypeHandler` 的 `toObject` 方法调用：
```java
import java

from MethodAccess call, Method method
where method.hasName("toObject") and 
      method.getDeclaringType().getASupertype().hasQualifiedName("org.apache.struts2.rest.handler", "ContentTypeHandler") and 
      call.getMethod() = method
select call
```

改进查询方式，支持隐式继承：
```java
import java

from MethodAccess call, Method method
where method.hasName("toObject") and 
      method.getDeclaringType().getAnAncestor().hasQualifiedName("org.apache.struts2.rest.handler", "ContentTypeHandler") and 
      call.getMethod() = method
select call
```

---

## 数据流分析

### 本地数据流

**本地数据流**：分析一个方法内的变量流动情况。例如，用于跟踪 `Spring` 中表达式的解析：
```java
import java
import semmle.code.java.frameworks.spring.SpringController
import semmle.code.java.dataflow.TaintTracking

from Call call, Callable parseExpression, SpringRequestMappingMethod route
where call.getCallee() = parseExpression and 
      parseExpression.getDeclaringType().hasQualifiedName("org.springframework.expression", "ExpressionParser") and 
      parseExpression.hasName("parseExpression") and 
      TaintTracking::localTaint(DataFlow::parameterNode(route.getARequestParameter()), 
                                DataFlow::exprNode(call.getArgument(0)))
select route.getARequestParameter(), call
```

### 全局数据流

**全局数据流**：需要继承 `DataFlow::Configuration`，重写 `isSource` 和 `isSink` 方法：
```java
class MyConfig extends DataFlow::Configuration {
  MyConfig() { this = "Myconfig" }
  override predicate isSource(DataFlow::Node source) { ... }
  override predicate isSink(DataFlow::Node sink) { ... }
}
```

---

## 污点跟踪分析

**全局污点跟踪**：继承 `TaintTracking::Configuration` 并实现 `isSource` 和 `isSink`：
```java
import semmle.code.java.dataflow.TaintTracking
import java

class VulConfig extends TaintTracking::Configuration {
  VulConfig() { this = "myConfig" }
  override predicate isSource(DataFlow::Node source) { ... }
  override predicate isSink(DataFlow::Node sink) { ... }
}

from VulConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "source are"
```

---

## 白盒扫描

CodeQL 提供大量内置漏洞扫描规则，可以直接用来分析源码。

### 扫描命令
```bash
codeql database analyze source_database_name qllib/java/ql/src/codeql-suites/java-security-extended.qls \
  --format=csv --output=java-results.csv
```

### 自定义规则
自定义规则需包含元数据，例如：
```java
/**
 * @name 不完整的正则表达式匹配
 * @description 使用不转义的点号匹配主机名可能导致匹配范围过大。
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.8
 * @precision high
 * @id go/incomplete-hostname-regexp
 * @tags correctness, security, external/cwe/cwe-20
 */
```

# 白盒扫描：基础技术与案例解析

白盒扫描是一种安全测试方法，通过分析源代码发现潜在的安全漏洞。**CodeQL** 是一种功能强大的代码分析工具，广泛应用于白盒扫描中。它提供了一套标准的漏洞查询库，开发者和安全工程师可以直接利用这些库扫描代码中的常见安全问题。

本文将详细介绍白盒扫描的基本技术概念，逐步讲解相关案例，并分享一些实际的参考资源，帮助大家更好地理解和应用 CodeQL。

---

## 什么是白盒扫描？

白盒扫描通过检查程序的源代码或编译后的字节码，分析潜在的安全问题。这种方法不同于黑盒测试（运行时测试），它可以在代码未运行时发现深层次的漏洞。

CodeQL 是 GitHub 提供的一种代码查询语言，类似 SQL，可以查询代码中的模式或问题。它支持多种语言，如 Java、Python、C++ 等，为开发者提供了一种高效定位漏洞的手段。

---

## 常见漏洞与 CodeQL 查询案例

以下是白盒扫描中常见的漏洞类型及其对应的 CodeQL 查询脚本。

### 1. **Zip Slip（文件覆盖漏洞）**

- **描述**：通过解压恶意 ZIP 文件，攻击者可以覆盖任意文件。
- **案例**：[ZipSlip.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-022/ZipSlip.ql)
- **技术细节**：
  - Zip 解压路径未进行验证，导致文件解压到不安全位置。
  - 修复建议：检查解压路径，限制解压范围。

---

### 2. **命令注入**

- **描述**：未经处理的用户输入被直接传递给系统命令，可能导致任意代码执行。
- **案例**：
  - [ExecUnescaped.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-078/ExecUnescaped.ql)
  - [ExecTainted.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-078/ExecTainted.ql)
- **技术细节**：
  - 典型漏洞代码：`Runtime.getRuntime().exec(userInput)`
  - 修复建议：验证和过滤用户输入，使用安全的命令执行库。

---

### 3. **Cookie 安全问题**

- **描述**：未加密的 Cookie 或未设置 `HttpOnly` 和 `Secure` 标志。
- **案例**：
  - [CleartextStorageCookie.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-312/CleartextStorageCookie.ql)
  - [InsecureCookie.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-614/InsecureCookie.ql)
- **技术细节**：
  - 漏洞危害：Cookie 被窃取后可能导致会话劫持。
  - 修复建议：启用加密传输，设置 `HttpOnly` 和 `Secure` 属性。

---

### 4. **跨站脚本攻击（XSS）**

- **描述**：恶意脚本注入网页，导致用户信息泄露。
- **案例**：[XSS.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-079/XSS.ql)
- **技术细节**：
  - 典型漏洞代码：`response.getWriter().write(userInput)`
  - 修复建议：对输出内容进行 HTML 编码，使用安全框架。

---

### 5. **依赖漏洞**

- **描述**：使用的第三方库包含已知漏洞。
- **案例**：
  - [MavenPomDependsOnBintray.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-1104/MavenPomDependsOnBintray.ql)
  - [InsecureDependencyResolution.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-829/InsecureDependencyResolution.ql)
- **技术细节**：
  - 修复建议：定期更新依赖项，使用工具检查依赖库安全性。

---

### 6. **反序列化漏洞**

- **描述**：通过不安全的对象反序列化执行恶意代码。
- **案例**：[UnsafeDeserialization.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-502/UnsafeDeserialization.ql)
- **技术细节**：
  - 修复建议：避免反序列化不可信数据，使用白名单机制。

---

### 7. **HTTP 头注入**

- **描述**：未过滤的输入被注入到 HTTP 头中。
- **案例**：
  - [NettyResponseSplitting.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-113/NettyResponseSplitting.ql)
  - [ResponseSplitting.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-113/ResponseSplitting.ql)
- **技术细节**：
  - 修复建议：验证和编码所有 HTTP 头输入。

---

### 8. **URL 跳转漏洞**

- **描述**：未验证的用户输入导致不安全的重定向。
- **案例**：[UrlRedirect.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-601/UrlRedirect.ql)

---

### 9. **SQL 注入**

- **描述**：用户输入未处理直接用于 SQL 查询。
- **案例**：
  - [SqlTainted.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-089/SqlTainted.ql)
  - [SqlUnescaped.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-089/SqlUnescaped.ql)
- **技术细节**：
  - 使用参数化查询或 ORM 工具。

---

## 推荐资源

以下是一些推荐阅读的资源，帮助您深入学习 CodeQL 和白盒扫描技术：

1. [CodeQL 学习教程](https://github.com/SummerSec/learning-codeql)
2. [安全客上的 CodeQL 入门](https://www.anquanke.com/post/id/203674)
3. [Fynch3r 的 CodeQL 系列文章](https://fynch3r.github.io/tags/CodeQL/)
4. [FreeBuf 的 CodeQL 技术解析](https://www.freebuf.com/articles/web/283795.html)

---

## 总结

白盒扫描结合 CodeQL 提供了强大的代码审计能力。通过了解上述漏洞及其技术细节，开发者可以更加高效地识别和修复代码中的安全问题，从而提高应用的整体安全性。
