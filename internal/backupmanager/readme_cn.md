## `backupmanager.go` 文件逻辑和用法详解 (中文)

`backupmanager.go` 文件定义了一个用于管理 Helm Chart 备份和恢复的核心组件。其主要目的是在 Helm Release 安装或升级之前，自动创建 Chart 及其配置值的版本化备份，并提供从这些备份中恢复、升级或删除的功能。

### 核心功能和组件:

#### 常量 (Constants):

-   `backupDirName`: `"chart"`，在每个备份实例目录中，存放 Chart 文件的子目录名称。
-   `valuesFileName`: `"values.yaml"`，存放该备份对应的 Helm Values 的文件名。
-   `metadataFileName`: `"metadata.json"`，存放该备份元数据信息的文件名。
-   `backupIDTimestampFormat`: `"20060102-150405.000000"`，用于生成基于时间戳的唯一备份 ID 的格式。

#### `BackupMetadata` 结构体:

定义了单个备份实例的元数据。字段包括：

-   `BackupID`: 备份的唯一标识符。
-   `Timestamp`: 备份创建的时间戳。
-   `ReleaseName`: 对应的 Helm Release 名称。
-   `ChartName`: 被备份的 Chart 的名称 (从 `Chart.yaml` 读取)。
-   `ChartVersion`: 被备份的 Chart 的版本 (从 `Chart.yaml` 读取)。
-   `AppVersion`: 被备份的 Chart 的应用版本 (可选, 从 `Chart.yaml` 读取)。
-   `Description`: 被备份的 Chart 的描述 (可选, 从 `Chart.yaml` 读取)。

这些元数据会以 JSON 格式保存在每个备份实例目录下的 `metadata.json` 文件中。

#### `ChartYAML` 结构体:

一个简化的 `Chart.yaml` 文件结构，用于解析备份 Chart 中的 `Chart.yaml` 文件，以提取必要的元数据 (如名称、版本等)。

#### `Manager` 接口:

定义了 Chart 备份和恢复操作的统一接口。这种设计允许未来可能实现其他存储后端 (例如 S3, Azure Blob Storage 等)。主要方法包括：

-   `BackupRelease`: 创建一个新的备份。
-   `ListBackups`: 列出指定 Release 的所有可用备份。
-   `GetBackupDetails`: 获取特定备份的详细信息 (包括 Chart 路径、Values 文件路径和元数据)。
-   `RestoreRelease`: 从指定备份恢复 Helm Release (通常涉及卸载当前版本，然后从备份安装)。
-   `UpgradeToBackup`: 使用指定备份的内容升级现有的 Helm Release。
-   `DeleteBackup`: 删除一个特定的备份。
-   `PruneBackups`: 清理旧的备份，只保留指定数量的最新备份。

#### `FileSystemBackupManager` 结构体:

`Manager` 接口的一个具体实现，使用本地文件系统作为备份存储。

-   `baseBackupPath`: 字符串类型，指定所有备份存储的根目录。备份的目录结构通常是：`<baseBackupPath>/<releaseName>/<backupID>/`。
-   `log`: 一个日志记录函数，用于输出操作信息。

#### `NewFileSystemBackupManager` 函数:

`FileSystemBackupManager` 的构造函数。

-   接收 `baseBackupPath` 和一个可选的 `logger` 函数作为参数。
-   会检查 `baseBackupPath` 是否为空，并确保该目录存在 (如果不存在则创建)。
-   如果未提供 `logger`，则使用 `log.Printf` 作为默认日志记录器。

#### `FileSystemBackupManager` 的方法实现:

##### `BackupRelease(releaseName string, chartSourcePath string, values map[string]interface{}) (string, error)`:

1.  验证输入参数 (如 `releaseName`, `chartSourcePath` 不能为空)。
2.  生成一个基于当前 UTC 时间戳的唯一 `backupID`。
3.  构建备份实例的完整路径：`<baseBackupPath>/<releaseName>/<backupID>/`。
4.  创建此备份实例目录。
5.  **复制 Chart**: 使用内部的 `copyDirectory` 辅助函数，将 `chartSourcePath` (源 Chart 目录) 的内容完整复制到 `<backupInstancePath>/chart/` 子目录中。
6.  **读取 Chart 元数据**: 从复制到备份目录中的 `chart/Chart.yaml` 文件解析出 Chart 的名称、版本等信息，填充到 `BackupMetadata` 中。如果 `Chart.yaml` 不存在或解析失败，会记录警告但不会中断备份过程 (会使用默认值)。
7.  **保存 Values**: 将传入的 `values` (一个 `map[string]interface{}`) 序列化为 YAML 格式，并保存到 `<backupInstancePath>/values.yaml` 文件中。
8.  **创建并保存元数据**: 创建 `BackupMetadata` 结构体实例，填充所有信息 (包括上一步获取的 Chart 信息和当前的备份 ID、时间戳等)。
9.  将 `BackupMetadata` 实例序列化为 JSON 格式 (带缩进)，并保存到 `<backupInstancePath>/metadata.json` 文件中。
10. 如果在任何关键步骤失败 (如目录创建、文件复制、Values 或元数据写入失败)，会尝试删除已部分创建的备份实例目录，以保持清洁。

##### `ListBackups(releaseName string) ([]BackupMetadata, error)`:

1.  构建指定 `releaseName` 的备份根路径：`<baseBackupPath>/<releaseName>/`。
2.  读取该目录下的所有条目。
3.  遍历每个条目，如果是一个目录 (代表一个 `backupID`)，则尝试读取其下的 `metadata.json` 文件。
4.  将读取到的 JSON 内容反序列化为 `BackupMetadata` 对象。
5.  如果 `metadata.json` 不存在或解析失败，会记录警告并跳过该备份条目。
6.  将所有成功解析的 `BackupMetadata` 对象收集到一个列表中。
7.  最后，根据 `Timestamp` 字段对列表进行降序排序 (最新的备份在前)。

##### `GetBackupDetails(releaseName string, backupID string) (chartPath string, valuesFilePath string, metadata BackupMetadata, err error)`:

1.  构建特定 `backupID` 的备份实例路径。
2.  检查该路径是否存在，如果不存在则返回错误。
3.  读取并反序列化该备份实例下的 `metadata.json` 文件。
4.  构建并返回备份的 Chart 目录路径 (`<backupInstancePath>/chart/`) 和 Values 文件路径 (`<backupInstancePath>/values.yaml`)，以及解析出的元数据。
5.  同时检查 Chart 目录和 Values 文件是否存在，如果任一不存在，也返回错误。

##### `RestoreRelease(...)`:

1.  调用 `GetBackupDetails` 获取指定备份的 Chart 路径、Values 文件路径和元数据。
2.  读取备份的 `values.yaml` 文件内容，并反序列化为 `map[string]interface{}`。
3.  使用传入的 `helmClient` (一个 `helmutils.HelmClient` 实例) 尝试卸载当前 namespace 下同名的 Release。如果 Release 不存在，则忽略该错误；其他卸载错误会记录为警告。
4.  使用 `helmClient.InstallChart` 方法，从备份的 Chart 路径 (`chartPath`) 和备份的 Values (`valuesMap`) 来安装新的 Release。

##### `UpgradeToBackup(...)`:

1.  与 `RestoreRelease` 类似，首先获取备份详情并读取 Values。
2.  使用 `helmClient.UpgradeRelease` 方法，将当前 Release 升级到备份中定义的状态。它使用备份的 Chart 路径和 Values。`installIfMissing` 参数通常设置为 `true`，以便在 Release 不存在时也能执行安装。

##### `DeleteBackup(releaseName string, backupID string)`:

1.  构建指定 `backupID` 的备份实例路径。
2.  检查路径是否存在，不存在则报错。
3.  使用 `os.RemoveAll` 删除整个备份实例目录。

##### `PruneBackups(releaseName string, keepCount int)`:

1.  验证 `keepCount` (必须非负)。
2.  调用 `ListBackups` 获取该 Release 的所有备份 (已按时间降序排列)。
3.  如果备份数量小于等于 `keepCount`，则无需清理，直接返回。
4.  否则，遍历列表中从 `keepCount` 索引开始到末尾的备份 (这些是较旧的备份)。
5.  对每个需要清理的备份，调用 `DeleteBackup` 将其删除。
6.  记录删除操作，如果删除过程中发生错误，会记录错误但会尝试继续清理其他备份。

#### 辅助函数 (Helper Functions):

-   **`copyFile(src, dst string) error`**: 用于复制单个文件。它会尝试保留源文件的权限模式。
-   **`copyDirectory(src, dst string) error`**: 用于递归复制整个目录。它会复制子目录、文件，并尝试处理符号链接 (symlinks)，同时保留文件和目录的权限模式。

### 使用场景:

1.  **初始化**: 创建一个 `FileSystemBackupManager` 实例，提供一个基础备份路径。
2.  **备份**: 在执行 `helm install` 或 `helm upgrade` 之前，调用 `BackupRelease` 方法，传入 Release 名称、待部署的 Chart 的路径以及将用于部署的 Values。该方法会返回一个唯一的 `backupID`。
3.  **列出备份**: 调用 `ListBackups` 查看某个 Release 有哪些可用的备份。
4.  **恢复**: 如果需要回滚到某个历史状态，调用 `RestoreRelease`，并提供 `backupID` 和其他必要的 Helm 操作参数 (如 namespace, `helmClient` 实例等)。
5.  **基于备份升级**: 调用 `UpgradeToBackup`，其行为类似回滚，但使用 Helm 的升级流程。
6.  **管理备份**:
    *   调用 `DeleteBackup` 删除不再需要的特定备份。
    *   调用 `PruneBackups` 定期清理旧备份，以节省存储空间，例如只保留最近的 N 个备份。

### 文件系统结构:

所有备份都存储在 `baseBackupPath` 下，其结构如下：

```
<baseBackupPath>/
└── <releaseName1>/
    ├── <backupID1_timestamp>/
    │   ├── chart/              # 完整的 Helm Chart 目录副本
    │   │   ├── Chart.yaml
    │   │   ├── values.yaml
    │   │   ├── templates/
    │   │   └── ...
    │   ├── values.yaml         # 本次备份/部署时使用的 Values
    │   └── metadata.json       # 本次备份的元数据
    └── <backupID2_timestamp>/
        ├── chart/
        ├── values.yaml
        └── metadata.json
└── <releaseName2>/
    └── ...
```

这个包通过 `Manager` 接口提供了良好的抽象，使得如果未来需要将备份存储到云存储或其他地方，可以方便地替换掉 `FileSystemBackupManager` 这个实现，而上层逻辑基本不需要改动。