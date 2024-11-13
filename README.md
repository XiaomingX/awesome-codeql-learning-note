# Codeql 学习笔记
## Codeql 概述

1. Codeql 本质上就是写各种过滤条件和数据流跟踪，感觉像是在写面向对象的 SQL。建议先掌握面向对象的思想、一门面向对象的编程语言，以及 SQL 的编写。
2. Codeql 的工作原理主要是通过分析引擎来分析代码关系，生成一个代码数据库，然后可以用 QL 语言进行各种查询，比如找某个方法、某个类、方法引用，或者跟踪参数传递等。
3. Codeql 中的谓词其实就是把各种过滤条件封装成方法。
4. Java 中 "万物皆对象"，而 Codeql 中则是 "万物皆表达式"。
5. 在 lgtm 平台上不仅可以下载数据库，还可以搜索 QL。
6. 目录 `/ql/java/ql/src/Security` 下有一些官方的 Java 安全规则，可以直接使用。
7. `/ql/java/ql/src/experimental/Security` 目录下存放了一些 Java 实验性规则。

## 相关下载资源

- 文档：https://codeql.github.com/docs/codeql-cli/
- 二进制包：https://github.com/github/codeql-cli-binaries
- 示例项目：https://github.com/github/vscode-codeql-starter

- 数据库下载、在线查询、规则搜索：https://lgtm.com/

## 数据库生成步骤

**提示**：生成数据库之前，先确保被分析的程序可以正常运行。

1. 创建代码索引数据库，有了数据库之后就可以开始查询了。

   ```shell
   codeql database create <database> --language=<language-identifier>
   ```

   支持的语言及对应的 language 标识如下：

   | 语言                 | 标识        |
   | -------------------- | ----------- |
   | C/C++                | cpp         |
   | C#                   | csharp      |
   | Go                   | go          |
   | Java                 | java        |
   | JavaScript/TypeScript | javascript |
   | Python               | python      |
   | Ruby                 | ruby        |

2. 生成 Java 的代码扫描数据库：

   ```shell
   codeql database create D:\codeqldb/javasec --language=java --command="mvn clean install --file pom.xml -Dmaven.test.skip=true" --source-root=./javasec
   ```

   注：`source-root` 为源码路径，默认为当前目录，可不指定。

## 一些常用命令

在 CodeQL 中常用的构建和索引数据库的命令如下：

1. **跳过测试，构建项目**

   ```shell
   --command="mvn clean install --file pom.xml -Dmaven.test.skip=true"
   ```

2. **项目构建不会因为失败而中断**

   ```shell
   --command="mvn -fn clean install --file pom.xml -Dmaven.test.skip=true"
   ```

3. **包含 XML 文件**

   CodeQL 默认不包含非源代码文件，如 XML 文件。为了将 XML 文件添加到 CodeQL 数据库中，可使用以下命令：

   ```shell
   codeql database init --source-root=<src> --language=java <db>
   codeql database trace-command --working-dir=<src> <db> <java command>
   codeql database index-files --language=xml --include-extension .xml --working-dir=<src> <db>
   codeql database finalize <db>
   ```

   将上面的步骤拆分成 4 个命令，在 `index-files` 步骤中使用 `--include-extension .xml` 将 XML 文件包含到 CodeQL 的数据库中。

4. **包含 XML 文件的替代方案**

   另一种方案是在 `codeql-cli/java/tools/pre-finalize.cmd` 文件中插入如下代码来包含 XML 文件：

   ```shell
   --include "**/resources/**/*.xml"
   ```

## 更新数据库

当需要更新数据库时，可以使用以下命令：

```shell
codeql database upgrade database/javasec
```

参考文档：[CodeQL 数据库上传准备](https://help.semmle.com/lgtm-enterprise/admin/help/prepare-database-upload.html)

## 编译与非编译语言的数据库创建

对于不同类型的语言，数据库创建的方式略有不同：

- **编译型语言（如 Java）**：在创建索引数据库时，需要包含编译过程，以便 CodeQL 能够全面分析代码。
- **非编译型语言**：可以直接扫描文件，不需要额外的编译步骤。

对于 Go 语言，可以选择是否编译，具体视项目需求而定。

## 基础查询

### 过滤 `Method`

#### 1. 根据 Method 名称查询

以下查询会根据方法名称查找指定方法 `toObject`：

```java
import java

from Method method
where method.hasName("toObject")
select method
```

#### 2. 查找方法的类名

要在查询方法的同时也获取到声明此方法的类名，可以如下修改：

```java
import java

from Method method
where method.hasName("toObject")
select method, method.getDeclaringType()
```

#### 3. 根据 Method 名称和接口名称查询

比如，我们要查找 `ContentTypeHandler` 的所有子类中名为 `toObject` 的方法，可以使用以下代码：

```java
import java

from Method method
where method.hasName("toObject") 
  and method.getDeclaringType().getASupertype().hasQualifiedName("org.apache.struts2.rest.handler", "ContentTypeHandler")
select method
```

#### `Call` 和 `Callable`

- **`Callable`**：表示所有可以调用的方法或构造器的集合。
- **`Call`**：表示调用 `Callable` 的过程，例如方法调用或构造器调用。

### `MethodAccess` 过滤方法调用

`MethodAccess` 过滤方法调用，通常是通过查找方法并将其与 `MethodAccess.getMethod()` 进行比较来实现。

例如，查找 `ContentTypeHandler` 类中的 `toObject()` 方法的调用：

```java
import java

from MethodAccess call, Method method
where method.hasName("toObject") 
  and method.getDeclaringType().getASupertype().hasQualifiedName("org.apache.struts2.rest.handler", "ContentTypeHandler") 
  and call.getMethod() = method
select call
```

上述查询可能只能查到显式定义的类，比如 `JsonLibHandler`。我们可以改进代码，通过 `getAnAncestor()` 或 `getASupertype()` 来包括父类或祖先类型的匹配：

```java
import java

from MethodAccess call, Method method
where method.hasName("toObject") 
  and method.getDeclaringType().getAnAncestor().hasQualifiedName("org.apache.struts2.rest.handler", "ContentTypeHandler") 
  and call.getMethod() = method
select call
```

### 过滤构造方法

当 `File` 的参数为我们感兴趣的 `sink` 点时，可以定义如下的查询代码，以捕获 `File` 的构造方法：

```java
class FileConstruct extends ClassInstanceExpr {
    FileConstruct() {
        this.getConstructor().getDeclaringType*().hasQualifiedName("java.io", "File")
    }
}
``` 

该代码定义了一个 `FileConstruct` 类，用于检测 `java.io.File` 构造方法的调用。

## CodeQL Java 规则目录

CodeQL 提供了一些官方的规则集，可以直接使用，目录结构如下：

```
-java
--ql
---src
----Security          # 正式发布的规则
----experimental      # 实验中的规则
---lib
----semmle
-----code
------java           # 与各种框架相关的内容
```

## 数据流跟踪

### 本地数据流（Local Data Flow）分析 - SPEL

本地数据流指的是单个方法或可调用对象内部的数据流（当变量跳出该方法时，数据流即中断），它通常比全局数据流更快且更精确。

以下代码演示了本地数据流的分析，查找 Spring 框架中的 `parseExpression` 方法的调用：

```java
import java
import semmle.code.java.frameworks.spring.SpringController
import semmle.code.java.dataflow.TaintTracking

from Call call, Callable parseExpression, SpringRequestMappingMethod route
where
    call.getCallee() = parseExpression and 
    parseExpression.getDeclaringType().hasQualifiedName("org.springframework.expression", "ExpressionParser") and
    parseExpression.hasName("parseExpression") and 
    TaintTracking::localTaint(DataFlow::parameterNode(route.getARequestParameter()), DataFlow::exprNode(call.getArgument(0)))
select route.getARequestParameter(), call
```

### 全局数据流分析

在全局数据流分析中，需要继承 `DataFlow::Configuration` 类并重载 `isSource` 和 `isSink` 方法：

```java
class MyConfig extends DataFlow::Configuration {
  MyConfig() { this = "MyConfig" }

  override predicate isSource(DataFlow::Node source) {
    // 定义源节点
  }

  override predicate isSink(DataFlow::Node sink) {
    // 定义汇节点
  }
}
```

### 数据流断开的原因

1. **外部方法**：如果某些外部方法没有编译到数据库中，数据流会在这些方法处中断。
2. **复杂的字符串拼接**：例如使用 `append` 或其他字符串拼接，某些字符串传递可能需要手动处理。
3. **强制类型转换**：强制类型转换可能导致数据流中断。
4. **动态特性**：例如使用 `Class.forName`。CodeQL 提供了较好的反射支持，而其他工具如 Fortify 在这方面则稍显不足。

### `isAdditionalStep` 技巧

`isAdditionalStep` 可以用来在数据流分析中定位中断的位置。使用二分法逐步前移或后移 `sink`，直至找到中断点。

**冷知识**：数据流可混合使用，例如 `sink` 可以成为 `hasFlow` 表达式的一部分。

## 污点跟踪

在全局污点跟踪分析中，需要继承 `TaintTracking::Configuration` 类，并重载 `isSource` 和 `isSink` 方法：

```java
class VulConfig extends TaintTracking::Configuration {
  VulConfig() { this = "myConfig" }

  override predicate isSource(DataFlow::Node source) {
    // 定义污点源
  }

  override predicate isSink(DataFlow::Node sink) {
    // 定义污点汇
  }
}

from VulConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Source identified"
```

## 白盒扫描

CodeQL 的查询库（QL 库）集成了许多常见的安全漏洞，可以直接用于扫描项目源码，详细内容可查阅 CodeQL 官方的 Java 安全查询文档：

[CodeQL Java 安全查询文档](https://codeql.github.com/codeql-query-help/java/)

## 常见 Java 安全查询规则

以下是一些已经写好的 CodeQL 规则，用于检测常见的 Java 安全漏洞。可以直接在项目中使用这些规则：

1. **Zip Slip（Zip 解压覆盖任意文件）**  
   [ZipSlip.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-022/ZipSlip.ql)

2. **命令注入**  
   - [ExecUnescaped.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-078/ExecUnescaped.ql)  
   - [ExecTainted.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-078/ExecTainted.ql)

3. **Cookie 安全**  
   - [CleartextStorageCookie.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-312/CleartextStorageCookie.ql)  
   - [InsecureCookie.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-614/InsecureCookie.ql)

4. **跨站脚本攻击 (XSS)**  
   [XSS.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-079/XSS.ql)

5. **依赖漏洞**  
   - [MavenPomDependsOnBintray.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-1104/MavenPomDependsOnBintray.ql)  
   - [InsecureDependencyResolution.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-829/InsecureDependencyResolution.ql)

6. **反序列化**  
   [UnsafeDeserialization.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-502/UnsafeDeserialization.ql)

7. **HTTP 头注入**  
   - [NettyResponseSplitting.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-113/NettyResponseSplitting.ql)  
   - [ResponseSplitting.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-113/ResponseSplitting.ql)

8. **URL 跳转**  
   [UrlRedirect.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-601/UrlRedirect.ql)

9. **LDAP 注入**  
   [LdapInjection.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-090/LdapInjection.ql)

10. **SQL 注入**  
    - [SqlTainted.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-089/SqlTainted.ql)  
    - [SqlUnescaped.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-089/SqlUnescaped.ql)

11. **文件权限 & 目录注入**  
    - [ReadingFromWorldWritableFile.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-732/ReadingFromWorldWritableFile.ql)  
    - [TaintedPath.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-022/TaintedPath.ql)

12. **XML 注入**  
    [XXE.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-611/XXE.ql)

13. **SSL 校验**  
    [UnsafeHostnameVerification.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-297/UnsafeHostnameVerification.ql)

14. **弱加密**  
    [BrokenCryptoAlgorithm.ql](https://github.com/github/codeql/java/ql/src/Security/CWE/CWE-327/BrokenCryptoAlgorithm.ql)

15. **随机数种子可预测**  
    [PredictableSeed.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-335/PredictableSeed.ql)

## 使用 `codeql analyze` 命令执行查询

可以使用 `codeql analyze` 命令执行单个 `.ql` 文件、目录中的所有 `.ql` 文件，或使用 `.qls` 查询套件（suite）来运行一组查询。例如，要执行所有漏洞类查询，可以使用以下命令：

```shell
codeql database analyze source_database_name qllib/java/ql/src/codeql-suites/java-security-extended.qls --format=csv --output=java-results.csv
```

## 自定义查询的元数据规范

如果是自己编写的查询文件，要确保该文件符合规范，以便能用于 `analyze` 命令。以下是一个元数据示例：

```java
/**
 * @name Incomplete regular expression for hostnames
 * @description Matching a URL or hostname against a regular expression that contains an unescaped
 *              dot as part of the hostname might match more hostnames than expected.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.8
 * @precision high
 * @id go/incomplete-hostname-regexp
 * @tags correctness
 *       security
 *       external/cwe/cwe-20
 */
```

以上元数据示例包含了以下标签，用于描述查询的特性：

- `@name`：查询的名称
- `@description`：查询的描述
- `@kind`：查询的类型，如 `path-problem`
- `@problem.severity`：问题的严重性
- `@security-severity`：安全性严重度
- `@precision`：查询的精度，如 `high`
- `@id`：查询的唯一标识
- `@tags`：标签，标识查询所属的类别或主题

## CodeQL 相关学习资料

这里整理了一些学习 CodeQL 过程中收藏的文章和资源，方便深入理解和应用 CodeQL：

1. [CodeQL从入门到放弃 - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/web/283795.html)
2. [使用CodeQL挖掘fastjson利用链 - 先知社区](https://xz.aliyun.com/t/7482)
3. [CodeQL documentation](https://codeql.github.com/docs/)
4. [4hou 搜索 CodeQL 相关文章](https://www.4hou.com/search-post?page=4&keywords=codeql)
5. [代码分析平台CodeQL学习手记（十七） - 嘶吼 RoarTalk](https://www.4hou.com/posts/o6wX)
6. [Query console - LGTM](https://lgtm.com/query/lang:java/)
7. [使用CodeQL挖掘ofcms - 安全客](https://www.anquanke.com/post/id/203674)
8. [haby0/mark: notes](https://github.com/haby0/mark)
9. [codeql学习——污点分析 - 先知社区](https://xz.aliyun.com/t/7789)
10. [codeql学习笔记 - 知乎](https://zhuanlan.zhihu.com/p/354275826)
11. [GitHub/vscode-codeql-starter: VS Code CodeQL 起始项目](https://github.com/github/vscode-codeql-starter)
12. [CodeQL for Golang Practise(3)](http://f4bb1t.com/post/2020/12/16/codeql-for-golang-practise3/)
13. [CodeQL静态代码扫描之实现关联接口、入参、和危险方法](https://mp.weixin.qq.com/s/Rqo12z9mapwlj6wGHZ1zZA)
14. [CodeQL分析Vulnerability-GoApp - FreeBuf](https://www.freebuf.com/articles/web/253491.html)
15. [codeql反序列化分析](https://github.com/githubsatelliteworkshops/codeql)
16. [[原创]58集团白盒代码审计系统建设实践2](https://bbs.pediy.com/thread-266995.htm#msg_header_h1_4)
17. [楼兰的CodeQL笔记](https://mp.weixin.qq.com/mp/appmsgalbum?__biz=Mzg4ODU4ODYzOQ==&action=getalbum&album_id=1970201600723910658&scene=173&from_msgid=2247484983&from_itemidx=1&count=3&nolastread=1#wechat_redirect)
18. [CodeQL学习笔记 | Gamous'Site](http://blog.gamous.cn/post/codeql/)
19. [LGTM 查询 - Go 语言规则](https://lgtm.com/search?q=language%3Ago&t=rules)
20. [CodeQL 和代码扫描简介 - GeekMasher 博客](https://geekmasher.dev/posts/sast/codeql-introduction)
21. [CVE-2018-11776: CodeQL发现 Apache Struts RCE](https://mp.weixin.qq.com/s/LmOFGAhqAKiO8VDQW4vvLg)
22. [CodeQL 静态代码扫描之 RemoteFlowSource](https://mp.weixin.qq.com/s/jVZ3Op8FYBmiFAV3p0li3w)
23. [CodeQL 静态代码扫描之抽象类探究](https://mp.weixin.qq.com/s/KQso2nvWx737smunUHwXag)
24. [CodeQL 规则编写入门](https://mp.weixin.qq.com/s/sAUSgRAohFlmzwSkkWjp9Q)
25. [About LGTM - Help - LGTM](https://lgtm.com/help/lgtm/about-lgtm)
26. [LGTM 帮助文档](https://help.semmle.com/home/help/home.html)
27. [Capture the flag | GitHub Security Lab](https://securitylab.github.com/ctf/)
28. [CodeQL笔记 | LFYSec](https://lfysec.top/2020/06/03/CodeQL笔记/)
29. [CodeQL学习——CodeQL数据流分析 - bamb00 - 博客园](https://www.cnblogs.com/goodhacker/p/13583650.html)
30. [分类: codeql - 食兔人的博客](https://blog.ycdxsb.cn/categories/research/codeql/)
31. [CodeQL - butter-fly](https://yourbutterfly.github.io/note-site/module/semmle-ql/codeql/)
32. [CodeQL 数据流在 Java 中的使用](https://github.com/haby0/mark/blob/master/articles/2021/CodeQL-数据流在Java中的使用.md)
33. [GitHub/securitylab: 相关资源](https://github.com/github/securitylab)
34. [CodeQL从0到1 - 安全客](https://www.anquanke.com/post/id/255721)
35. [CodeQL挖掘React应用的XSS实践 | Image's blog](https://hexo.imagemlt.xyz/post/javascript-codeql-learning/)
36. [SummerSec/learning-codeql: 全网最全的CodeQL Java中文学习资料](https://github.com/SummerSec/learning-codeql)
37. [CodeQL查询帮助 - Go语言](https://codeql.github.com/codeql-query-help/go/#)
38. [CodeQL使用指南 - CSDN](https://blog.csdn.net/haoren_xhf/article/details/115064677)
39. [Apache Dubbo：RCE 挖掘 | GitHub Security Lab](https://securitylab.github.com/research/apache-dubbo/)
40. [使用CodeQL复现 Apache Kylin 命令执行漏洞](https://xz.aliyun.com/t/8240)
41. [CodeQL挖掘CVE-2020-10199 - 安全客](https://www.anquanke.com/post/id/202987)
42. [南大软件分析课程 - B站](https://space.bilibili.com/2919428?share_medium=iphone&share_plat=ios&share_session_id=6851D997-0AC6-4C67-B858-BD1E6258C548&share_source=COPY&share_tag=s_i&timestamp=1639480132&unique_k=8wQBAkV)
43. [各种语言危险 sink 点](https://github.com/haby0/sec-note)
44. [利用CodeQL分析Log4j漏洞](https://mp.weixin.qq.com/s/JYco8DysQNszMohH6zJEGw)
45. [图解CodeQL数据流](https://mp.weixin.qq.com/s/3mlRedFwPz31Rwe7VDBAuA)
46. [Firebasky的CodeQL学习笔记](https://github.com/Firebasky/CodeqlLearn)
47. [凡人哥的CodeQL学习资料](https://github.com/SummerSec/learning-codeql)
48. [Fynch3r的CodeQL笔记](https://fynch3r.github.io/tags/CodeQL/)
49. [CodeQL 目录、框架及实用内容](https://mp.weixin.qq.com/s/zSI157qJXYivSvyxHzXALQ)
50. [CodeQL 提升篇](https://tttang.com/archive/1415/)
51. [CodeQL与OpenJDK联动](https://fynch3r.github.io/%E8%AE%B0%E4%B8%80%E6%AC%A1CodeQL%E4%B8%8EOpenJDK%E7%9A%84%E8%81%94%E5%8A%A8/)
52. [深入理解CodeQL](https://github.com/ASTTeam/CodeQL)
53. [CodeQL 踩坑指南 - Java](https://tttang.com/archive/1497/)
54. [楼兰的CodeQL学习笔记](https://www.yuque.com/loulan-b47wt/rc30f7)
55. [CodeQL发现log4shell (CVE-2021-44228)漏洞的可能性](https://mp.weixin.qq.com/s/CkCnAAc0OafEcLiBV17wdg)

这些资源涵盖了 CodeQL 的基本入门、数据流分析、污点跟踪以及实战应用等多个方面，为深入学习 CodeQL 提供了广泛的参考资料。