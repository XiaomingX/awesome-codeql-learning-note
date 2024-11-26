### Javac 编译简述

Javac 的编译流程可以分为三个主要步骤，将 `.java` 文件编译为 `.class` 文件：

1. **解析并构建语法树**：将源代码解析成语法树，并存入符号表。
2. **处理注解**：在注解处理器中，对注解进行操作。
3. **生成字节码**：分析语法树并输出字节码到 `.class` 文件中。

---

### 详细流程

#### 1. **解析与填充符号表**

- **词法分析**  
  使用 `Scanner` 将源码中的字符流解析为 Token 流，Token 分为以下几类：
  - Java 关键字：如 `public`, `int`, `static` 等。
  - 自定义名称：如类名、方法名、变量名。
  - 运算符或逻辑符号：如 `+`, `-`, `&&` 等。  
  示例：`int x = y + 1;` 会被解析成对应的 Token 流。

- **语法分析**  
  使用 `TreeMaker` 构建抽象语法树（AST），每个语法节点表示代码结构中的一种语法元素（如包、类型、修饰符）。  
  示例代码的语法树展示了变量声明、方法定义等信息。

- **填充符号表**  
  符号表是一个存储符号信息（如类名、变量名）的数据结构，在编译阶段用于语义检查和代码生成。  
  - 将类中所有符号加入符号表。
  - 解析符号表中的类及其继承关系。

---

#### 2. **注解处理**

- **注解解析**  
  支持 JSR-269 标准，在编译期间处理注解。  
  注解处理器可以操作语法树，对其增删改查。修改后的语法树会被重新解析，直到所有注解处理器停止修改为止。

---

#### 3. **语义分析与代码生成**

- **语义分析**  
  通过检查上下文逻辑，验证代码的合法性：
  - 标注检查：如变量是否已声明、数据类型是否匹配。
  - 数据流分析：检查变量是否初始化、方法路径是否完整、异常是否被处理。

- **解语法糖**  
  将高级语法（如泛型、自动装箱）还原为基础语法。

- **生成字节码**  
  最终将语法树和符号表转换为 `.class` 文件中的字节码，由 `Gen` 类完成。

---

通过以上流程，Java 编译器确保了源代码被准确地翻译为可执行的字节码。


### 简单表达方式重新描述

#### JCTree 简介
JCTree 是抽象语法树（AST）的核心类，其中包含了各种语法节点的定义，比如类、方法、变量等。我们通过调用 `accept()` 方法，使用一个 `Visitor` 对象可以遍历和操作这些语法节点。

```java
public abstract void accept(JCTree.Visitor visitor);
```

#### Visitor 访问器
`Visitor` 是一个抽象类，提供了对不同语法节点的访问方法。常见子类有：
- **TreeScanner**：扫描所有节点。
- **TreeTranslator**：扫描并可修改节点。

以下是常用的访问方法：
- **visitClassDef**: 访问类定义节点。
- **visitMethodDef**: 访问方法定义节点。
- **visitVarDef**: 访问变量定义节点。
- **visitBlock**: 访问代码块。

#### 主要节点类型
- **JCStatement**: 表示语句的基类，常见子类包括 `JCBlock`（代码块）、`JCReturn`（返回语句）等。
- **JCExpression**: 表示表达式的基类，常见子类有 `JCBinary`（二元表达式）、`JCLiteral`（字面量）等。

#### 常见节点说明
1. **类定义** (`JCClassDecl`)
   - 包含类名、修饰符、继承的父类和实现的接口。
   - 例子：创建一个类节点。
     ```java
     treeMaker.ClassDef(treeMaker.Modifiers(Flags.PUBLIC), names.fromString("MyClass"), ...);
     ```

2. **方法定义** (`JCMethodDecl`)
   - 包含方法名、参数、返回类型等信息。
   - 例子：定义一个 `setName` 方法。
     ```java
     treeMaker.MethodDef(...);
     ```

3. **变量定义** (`JCVariableDecl`)
   - 表示变量名、类型和初始值。
   - 例子：定义变量 `x = 1`。
     ```java
     treeMaker.VarDef(treeMaker.Modifiers(Flags.PRIVATE), names.fromString("x"), treeMaker.TypeIdent(TypeTag.INT), treeMaker.Literal(1));
     ```

4. **字面量** (`JCLiteral`)
   - 表示常量值，如字符串或数字。
   - 例子：创建字符串 `"}"`。
     ```java
     treeMaker.Literal("}");
     ```

5. **赋值语句** (`JCAssign`)
   - 表示 `x = 1` 这样的语句。
   - 例子：
     ```java
     treeMaker.Assign(treeMaker.Ident(names.fromString("x")), treeMaker.Literal(1));
     ```

6. **二元操作符** (`JCBinary`)
   - 表示运算符两边的表达式，如 `1 + 1`。
   - 例子：
     ```java
     treeMaker.Binary(JCTree.Tag.PLUS, treeMaker.Literal(1), treeMaker.Literal(1));
     ```

7. **if 语句** (`JCIf`)
   - 表示 `if-else` 结构。
   - 例子：
     ```java
     treeMaker.If(cond, thenPart, elsePart);
     ```

8. **循环结构**
   - **for 循环** (`JCForLoop`): 包括初始化、条件和步进部分。
   - **增强 for 循环** (`JCEnhancedForLoop`): 表示 `for (var : collection)`。
   - **while 循环** (`JCWhileLoop`): 包含条件和循环体。

9. **异常处理**
   - **try** (`JCTry`): 包含 `try`、`catch` 和 `finally` 块。
   - **throw** (`JCThrow`): 表示抛出异常。

10. **三目运算符** (`JCConditional`)
    - 表示 `cond ? true : false`。

#### 示例
以下是一些常用语法节点的创建例子：
1. **创建变量**：
   ```java
   treeMaker.VarDef(treeMaker.Modifiers(Flags.PRIVATE), names.fromString("x"), treeMaker.TypeIdent(TypeTag.INT), treeMaker.Literal(1));
   ```
2. **if-else 语句**：
   ```java
   treeMaker.If(cond, thenPart, elsePart);
   ```
3. **for 循环**：
   ```java
   treeMaker.ForLoop(init, cond, step, body);
   ```

总之，JCTree 提供了丰富的语法节点，结合 `Visitor` 可以灵活地访问和修改 Java 的抽象语法树。


### 抽象语法树 (AST) 简单介绍与实操

#### 什么是AST？

抽象语法树（AST）是代码的结构化表示，拿到AST就相当于拿到了整个代码的模型。通过操作AST，可以直接在编译阶段修改代码逻辑，比如：

- 添加或删除日志；
- 检查对象调用是否为空；
- 应用特定语法规则并优化代码；
- 批量增删改查代码。

#### AST的优缺点

- **优点**：操作AST属于编译器级别，对程序运行无影响，效率高。
- **缺点**：官方文档少，操作复杂，需要自己摸索。

---

### 实操示例：通过AST清除日志

1. **设置Gradle配置**  
创建一个Java Library模块，配置必要的依赖项。

```gradle
apply plugin: 'java-library'

dependencies {
    implementation fileTree(include: ['*.jar'], dir: 'libs')
    implementation 'com.google.auto.service:auto-service:1.0-rc2'
    implementation files('libs/tools.jar')
    implementation project(':annotations')
}
```

2. **编写AST处理器**  
实现一个 `ASTProcessor`，在编译期间访问抽象语法树节点。

```java
@AutoService(Processor.class)
@SupportedSourceVersion(SourceVersion.RELEASE_8)
public class ASTProcessor extends AbstractProcessor {
    private Messager messager;
    private Trees trees;
    private TreeMaker treeMaker;
    private Names names;

    @Override
    public synchronized void init(ProcessingEnvironment processingEnvironment) {
        super.init(processingEnvironment);
        messager = processingEnvironment.getMessager();
        trees = Trees.instance(processingEnvironment);
        Context context = ((JavacProcessingEnvironment) processingEnvironment).getContext();
        treeMaker = TreeMaker.instance(context);
        names = Names.instance(context);
    }

    @Override
    public Set<String> getSupportedAnnotationTypes() {
        return Set.of("*");
    }

    @Override
    public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
        for (Element element : roundEnv.getRootElements()) {
            if (element.getKind() == ElementKind.CLASS) {
                JCTree tree = (JCTree) trees.getTree(element);
                tree.accept(new LogClearTranslator(messager));
            }
        }
        return false;
    }
}
```

3. **实现日志清除逻辑**  
通过遍历代码块，去除包含日志的行。

```java
public class LogClearTranslator extends TreeTranslator {
    private static final String LOG_TAG = "Log.";
    private final Messager messager;

    public LogClearTranslator(Messager messager) {
        this.messager = messager;
    }

    @Override
    public void visitBlock(JCTree.JCBlock block) {
        super.visitBlock(block);
        List<JCTree.JCStatement> newStatements = List.nil();
        for (JCTree.JCStatement statement : block.getStatements()) {
            if (!statement.toString().contains(LOG_TAG)) {
                newStatements = newStatements.append(statement);
            } else {
                messager.printMessage(Diagnostic.Kind.NOTE, "Removed log: " + statement);
            }
        }
        block.stats = newStatements;
    }
}
```

结果：日志被成功清除，编译后的`.class`文件中已无日志语句。

---

### 难度升级：自动生成Getter、Setter等方法

1. **自定义注解**  
通过 `@Data` 注解标记需要处理的类。

```java
@Target({ElementType.TYPE})
@Retention(RetentionPolicy.SOURCE)
public @interface Data {}
```

2. **生成Getter方法**  
为每个字段创建 `getXxx()` 方法。

```java
private JCTree.JCMethodDecl makeGetterMethod(JCTree.JCVariableDecl field) {
    return treeMaker.MethodDef(
        treeMaker.Modifiers(Flags.PUBLIC),
        getterMethodName(field),
        field.vartype,
        List.nil(),
        List.nil(),
        List.nil(),
        treeMaker.Block(0, List.of(treeMaker.Return(
            treeMaker.Select(treeMaker.Ident(names.fromString("this")), field.name)
        ))),
        null
    );
}
```

3. **生成Setter方法**  
为每个字段创建 `setXxx()` 方法。

```java
private JCTree.JCMethodDecl makeSetterMethod(JCTree.JCVariableDecl field) {
    return treeMaker.MethodDef(
        treeMaker.Modifiers(Flags.PUBLIC),
        setterMethodName(field),
        treeMaker.TypeIdent(TypeTag.VOID),
        List.nil(),
        List.of(treeMaker.VarDef(
            treeMaker.Modifiers(Flags.PARAMETER), field.name, field.vartype, null
        )),
        List.nil(),
        treeMaker.Block(0, List.of(treeMaker.Exec(treeMaker.Assign(
            treeMaker.Select(treeMaker.Ident(names.fromString("this")), field.name),
            treeMaker.Ident(field.name)
        )))),
        null
    );
}
```

4. **生成 `toString`、`hashCode`、`equals` 方法**  
通过AST动态生成这些常用方法，确保类的完整性。
