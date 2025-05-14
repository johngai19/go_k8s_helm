## `chartconfigmanager.go` 文件逻辑和用法详解 (中文)

`chartconfigmanager.go` 文件定义了一个用于管理 Helm Chart "产品" (Product) 的核心组件。产品在这里指的是一种预配置的、可参数化的 Helm Chart 模板。该模块的主要功能包括：定义新产品、列出和检索现有产品、从 Chart 模板中提取可配置的变量、以及用具体值实例化这些模板以生成可部署的 Helm Chart。

### 核心功能和组件:

#### 常量 (Constants):

-   `ProductMetaFilenameYAML`: `"product_meta.yaml"`，产品元数据的 YAML 文件名。
-   `ProductMetaFilenameJSON`: `"product_meta.json"`，产品元数据的 JSON 文件名。
-   `DefaultChartSubDir`: `"chart"`，在产品目录中，默认存放实际 Chart 文件的子目录名称。
-   `UnassignedVarError`: `"error"`，实例化时，如果模板中的变量未提供值，则返回错误。
-   `UnassignedVarEmpty`: `"empty"`，实例化时，如果模板中的变量未提供值，则替换为空字符串。
-   `UnassignedVarKeep`: `"keep"`，实例化时，如果模板中的变量未提供值，则保留原始占位符。

#### `VariableDefinition` 结构体:

描述在 Chart 模板中发现或定义的一个变量。

-   `Name`: 变量的名称 (例如，在模板中为 `@{variableName}` 中的 `variableName`)。
-   `Description`: (可选) 变量的描述。
-   `Default`: (可选) 变量的默认值。

#### `Product` 结构体:

代表一个预配置的 Chart 模板，通常作为 `baseProductsPath` 下的一个子目录存在。

-   `Name`: 产品的名称 (通常是其目录名)。
-   `Description`: 产品的描述。
-   `ChartPath`: 指向该产品实际 Chart 文件所在目录的路径 (绝对路径)。这可能是产品目录本身，也可能是产品目录下的一个子目录 (如 `chart/`)。
-   `Variables`: 该产品定义或发现的 `VariableDefinition` 列表。

产品目录可以包含一个可选的元数据文件 (`product_meta.yaml` 或 `product_meta.json`) 来进一步描述产品及其变量。

#### `Manager` 接口:

定义了管理 Chart 产品、提取变量和实例化操作的统一接口。这种设计允许未来可能实现其他存储或管理后端。主要方法包括：

-   `ListProducts()`: 列出所有可用的产品。
-   `GetProduct(productName string)`: 获取特定产品名称的详细信息。
-   `ExtractVariablesFromPath(path string)`: 扫描给定路径 (通常是一个 Chart 目录) 中的所有文件，识别并提取出所有 `@{variable}` 形式的占位符。
-   `InstantiateProduct(productNameOrPath string, variables map[string]interface{}, outputPath string, unassignedVarAction string)`: 获取一个产品 (通过名称) 或一个直接的 Chart 路径，使用提供的 `variables` 替换其模板中的占位符，并将结果输出到 `outputPath`。`unassignedVarAction` 参数控制当模板中的变量没有在 `variables` 中提供值时的行为。
-   `ValidateChartFiles(chartPath string)`: 检查给定 Chart 路径下的 YAML 和 JSON 文件结构是否有效。
-   `DefineProduct(productName string, baseChartPath string, productMetadata *Product)`: 定义一个新产品。这通常涉及在 `baseProductsPath` 下创建新的产品目录，从 `baseChartPath` 复制基础 Chart 内容，并根据提供的 `productMetadata` (可选) 生成元数据文件。

#### `FileSystemProductManager` 结构体:

`Manager` 接口的一个具体实现，使用本地文件系统来存储和管理产品定义。

-   `baseProductsPath`: 字符串类型，指定所有产品定义存储的根目录。每个产品对应此根目录下的一个子目录。
-   `log`: 一个日志记录函数，用于输出操作信息。

#### `NewFileSystemProductManager` 函数:

`FileSystemProductManager` 的构造函数。

-   接收 `baseProductsPath` (产品定义的根目录) 和一个可选的 `logger` 函数作为参数。
-   会检查 `baseProductsPath` 是否为空，并确保该目录存在 (如果不存在则创建)。
-   如果未提供 `logger`，则使用 `log.Printf` 作为默认日志记录器。

#### `FileSystemProductManager` 的方法实现:

##### `loadProductMetadata(productDirPath string) (Product, error)` (内部辅助函数):

-   尝试从指定的产品目录 (`productDirPath`) 加载 `product_meta.yaml` 或 `product_meta.json` 文件。
-   如果元数据文件中未指定 `ChartPath`，它会尝试探测：首先检查 `productDirPath/chart/Chart.yaml` 是否存在，然后检查 `productDirPath/Chart.yaml` 是否存在。如果都找不到，`ChartPath` 可能为空或回退到 `productDirPath`。

##### `ListProducts() ([]Product, error)`:

1.  读取 `baseProductsPath` 目录下的所有条目。
2.  遍历每个条目，如果是一个目录，则认为它是一个产品。
3.  对每个产品目录，调用 `loadProductMetadata` 加载其元数据。
4.  确保返回的 `Product` 结构中的 `Name` 字段与目录名一致，并且 `ChartPath` 是一个经过解析的有效路径 (通常是绝对路径)。
5.  收集所有产品信息并返回列表。

##### `GetProduct(productName string) (*Product, error)`:

1.  根据 `productName` 构建产品目录的完整路径。
2.  检查该目录是否存在且确实是一个目录。
3.  调用 `loadProductMetadata` 加载元数据。
4.  如果元数据加载失败但目录存在，会返回一个包含基本信息的 `Product` 结构 (名称和推断的 `ChartPath`)。
5.  确保返回的 `Product` 结构中的 `Name` 和 `ChartPath` 正确设置。

##### `ExtractVariablesFromPath(path string) ([]VariableDefinition, error)`:

1.  验证 `path` 是否存在且为目录。
2.  使用 `filepath.WalkDir` 递归遍历指定 `path` 下的所有文件 (会跳过 `.git`, `.idea` 等常见目录以及二进制文件)。
3.  读取每个文本文件的内容，并使用 `variableRegex` (正则表达式 `@{([a-zA-Z0-9_.-]+)}`) 查找所有匹配的变量占位符。
4.  收集所有唯一的变量名，并将其作为 `VariableDefinition` 列表返回 (按名称排序)。

##### `InstantiateProduct(productNameOrPath string, variables map[string]interface{}, outputPath string, unassignedVarAction string) (string, error)`:

1.  **解析源路径**:
    *   如果 `productNameOrPath` 看起来像一个产品名称 (不是绝对路径且不包含路径分隔符)，则调用 `GetProduct` 获取产品的 `ChartPath` 作为源路径。
    *   否则，将其视为一个直接的文件系统路径，并转换为绝对路径。
2.  验证源路径是否存在。
3.  **预检查 (如果 `unassignedVarAction == UnassignedVarError`)**: 调用 `ExtractVariablesFromPath` 获取源 Chart 中的所有变量，然后检查 `variables` map 是否提供了所有这些变量的值。如果有缺失，则返回错误。
4.  **准备输出路径**: 将 `outputPath` 转换为绝对路径。如果已存在，则先删除，然后重新创建，以确保输出目录是干净的。
5.  **遍历和替换**: 使用 `filepath.WalkDir` 遍历源路径 (`sourcePath`)：
    *   对于目录，在 `outputPath` 中创建对应的目录结构 (跳过 `.git` 等)。
    *   对于文件：
        *   跳过已知的二进制文件扩展名 (如 `.png`, `.jpg`, `.zip` 等) 和通过内容检测到的二进制文件 (包含 null 字节)，这些文件会直接复制。
        *   对于文本文件，读取内容，然后使用 `variableRegex.ReplaceAllStringFunc` 替换所有 `@{variableName}` 占位符：
            *   如果在 `variables` map 中找到 `variableName` 对应的值，则进行替换。
            *   如果未找到，则根据 `unassignedVarAction` 的值执行相应操作 (替换为空字符串、保留占位符)。
        *   将修改后的内容写入到 `outputPath` 中对应的文件，并保留源文件的权限模式。
6.  **验证**: 实例化完成后，调用 `ValidateChartFiles` 验证输出目录中的 Chart 文件结构是否有效。如果验证失败，会返回错误，但已实例化的文件会保留。
7.  返回成功实例化的 Chart 的绝对路径。

##### `ValidateChartFiles(chartPath string) error`:

1.  使用 `filepath.WalkDir` 遍历 `chartPath` 下的所有文件。
2.  对于 `.yaml` 或 `.yml` 文件，尝试使用 `yaml.Unmarshal` 解析其内容。
3.  对于 `.json` 文件，尝试使用 `json.Unmarshal` 解析其内容。
4.  收集所有解析错误。如果存在任何错误，则返回一个包含所有错误信息的聚合错误。

##### `DefineProduct(productName string, baseChartPath string, productMetadata *Product) error`:

1.  验证 `productName` 和 `baseChartPath` 不为空。
2.  构建新产品的目录路径 (`<baseProductsPath>/<productName>`)，如果已存在则报错。
3.  创建产品目录。
4.  确定 Chart 文件在产品目录中的目标子目录 (默认为 `chart/`，或从 `productMetadata.ChartPath` 获取相对路径)。
5.  使用内部的 `copyDirectory` 辅助函数将 `baseChartPath` 的内容复制到上述目标子目录。
6.  如果提供了 `productMetadata`：
    *   确保 `productMetadata.Name` 与 `productName` 一致。
    *   将 `productMetadata.ChartPath` 更新为 Chart 在产品目录中的绝对路径。
    *   将 `productMetadata` 序列化为 YAML 并写入到产品目录下的 `product_meta.yaml` 文件。
7.  如果没有提供 `productMetadata`，则创建一个包含基本信息 (名称和 Chart 路径) 的默认元数据并尝试写入 `product_meta.yaml`。

#### 辅助函数 (Helper Functions):

-   **`bytesContainBinary(data []byte) bool`**: 一个简单的启发式函数，通过检查数据中是否包含 null 字节 (0x00) 来判断内容是否可能为二进制。
-   **`copyFile(src, dst string) error`**: 用于复制单个文件，并尝试保留源文件的权限模式。
-   **`copyDirectory(src, dst string) error`**: 用于递归复制整个目录，包括子目录和文件，并尝试处理符号链接，同时保留文件和目录的权限模式。会跳过常见的版本控制和 IDE 相关的目录 (如 `.git`, `.idea` 等)。

### 使用场景:

1.  **初始化**:
    ```go
    import "go_k8s_helm/internal/chartconfigmanager"
    // ...
    pm, err := chartconfigmanager.NewFileSystemProductManager("./chart_products", log.Printf)
    if err != nil {
        // handle error
    }
    ```
    这将创建一个管理器，产品定义将存储在 `./chart_products` 目录下。

2.  **定义一个新产品**:
    假设有一个基础 Chart 模板位于 `./base-charts/my-app-chart`。
    ```go
    productMeta := &chartconfigmanager.Product{
        Description: "My awesome application product",
        Variables: []chartconfigmanager.VariableDefinition{
            {Name: "replicaCount", Description: "Number of replicas", Default: "1"},
            {Name: "imageTag", Description: "Docker image tag"},
        },
        // ChartPath can be relative to the product dir, e.g., "chart" or "helm/mychart"
        // If empty, defaults to "chart"
    }
    err := pm.DefineProduct("my-app-v1", "./base-charts/my-app-chart", productMeta)
    // 这会在 ./chart_products/my-app-v1/ 目录下创建产品，
    // 并将 ./base-charts/my-app-chart/ 的内容复制到 ./chart_products/my-app-v1/chart/ (默认情况下)
    // 同时创建 ./chart_products/my-app-v1/product_meta.yaml
    ```

3.  **列出所有产品**:
    ```go
    products, err := pm.ListProducts()
    for _, p := range products {
        fmt.Printf("Product: %s, Chart Path: %s\n", p.Name, p.ChartPath)
    }
    ```

4.  **获取特定产品详情**:
    ```go
    product, err := pm.GetProduct("my-app-v1")
    if err == nil {
        fmt.Printf("Details for %s: %+v\n", product.Name, product)
    }
    ```

5.  **从 Chart 模板提取变量**:
    ```go
    vars, err := pm.ExtractVariablesFromPath("./some_chart_template_dir")
    for _, v := range vars {
        fmt.Printf("Found variable: %s\n", v.Name)
    }
    ```

6.  **实例化产品 (生成可部署的 Chart)**:
    ```go
    values := map[string]interface{}{
        "replicaCount": 2,
        "imageTag":     "latest",
        "serviceType":  "LoadBalancer",
        // ... 其他在 my-app-v1 的 Chart 模板中定义的变量
    }
    instantiatedChartPath, err := pm.InstantiateProduct("my-app-v1", values, "./output_charts/my-app-instance-01", chartconfigmanager.UnassignedVarError)
    if err == nil {
        fmt.Printf("Chart instantiated to: %s\n", instantiatedChartPath)
        // 现在 ./output_charts/my-app-instance-01 目录包含了可直接用于 helm install 的 Chart
    }
    ```
    也可以直接实例化一个路径下的 Chart 模板：
    ```go
    instantiatedChartPath, err := pm.InstantiateProduct("./path/to/raw_chart_template", values, "./output_charts/raw_instance_01", chartconfigmanager.UnassignedVarKeep)
    ```

7.  **验证 Chart 文件**:
    ```go
    err := pm.ValidateChartFiles("./output_charts/my-app-instance-01")
    if err != nil {
        fmt.Printf("Chart validation failed: %v\n", err)
    } else {
        fmt.Println("Chart validation successful.")
    }
    ```

### 其他模块如何使用:

`chartconfigmanager` 主要被需要动态生成或管理 Helm Chart 配置的模块使用。一个典型的例子是 `cmd/productctl/main.go`，它提供了一个命令行界面来调用 `chartconfigmanager` 的各种功能：

-   `productctl list` 调用 `pm.ListProducts()`。
-   `productctl get <productName>` 调用 `pm.GetProduct()`。
-   `productctl extract-vars <chartPath>` 调用 `pm.ExtractVariablesFromPath()`。
-   `productctl instantiate <productNameOrPath> <outputPath> --values <values.yaml> --set key=val` 调用 `pm.InstantiateProduct()`。
-   `productctl validate <chartPath>` 调用 `pm.ValidateChartFiles()`。
-   `productctl define <productName> --base-chart-path <path>` 调用 `pm.DefineProduct()`。

任何需要以编程方式创建、参数化和验证 Helm Chart 的 Go 应用程序或工具都可以集成 `chartconfigmanager`。例如，一个 CI/CD 流水线中的步骤，或者一个更上层的应用部署平台，都可以利用它来管理 Chart 模板和其实例化过程。

### 文件系统结构 (示例):

如果 `baseProductsPath` 设置为 `./chart_products`，其结构可能如下：

```
./chart_products/
├── product-alpha/
│   ├── chart/                  # 实际的 Helm Chart 文件 (Chart.yaml, values.yaml, templates/, etc.)
│   │   ├── Chart.yaml
│   │   ├── values.yaml         # 模板化的 values.yaml，包含 @{...}
│   │   └── templates/
│   │       └── deployment.yaml # 包含 @{...}
│   └── product_meta.yaml       # 描述 product-alpha 及其变量
│
├── product-beta/
│   ├── helm-chart-files/       # Chart 文件也可以在自定义的子目录中 (需在 meta 中指定 ChartPath)
│   │   ├── Chart.yaml
│   │   └── ...
│   └── product_meta.yaml
│
└── simple-chart-product/       # 如果 Chart 文件直接在产品目录下
    ├── Chart.yaml
    ├── values.yaml
    ├── templates/
    └── product_meta.yaml       # ChartPath 在这种情况下会指向 simple-chart-product 本身
```

这个模块通过 `Manager` 接口提供了良好的抽象，使得如果未来需要从其他来源 (如 Git 仓库、对象存储等) 加载和管理产品定义，可以方便地提供新的接口实现，而上层逻辑的改动会相对较小。