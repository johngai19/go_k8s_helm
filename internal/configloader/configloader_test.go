package configloader

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to create temporary config files for testing
func createTempConfFile(t *testing.T, dir string, name string, content string) string {
	t.Helper()
	filePath := filepath.Join(dir, name)
	err := os.WriteFile(filePath, []byte(content), 0644)
	require.NoError(t, err, "Failed to write temp config file")
	return filePath
}

func TestParseConfFile_Syntax(t *testing.T) {
	tempDir := t.TempDir()
	target := make(map[string]string)

	content := `
KEY1=value1
KEY2 = "value with spaces" # comment
KEY3 = 'another value'
# This is a comment line
KEY_UNQUOTED = unquoted_val # and a comment
KEY_UNQUOTED_SPACE = unquoted val with space # comment
KEY_EMPTY=
KEY_OVERWRITE=initial
KEY_OVERWRITE=final # final value
KEY_NO_COMMENT = nocommentvalue
KEY.WITH.DOTS = dotted_key_value
`
	path := createTempConfFile(t, tempDir, "test.conf", content)
	err := parseConfFile(path, target, "TEST_SYNTAX", "")
	require.NoError(t, err)

	assert.Equal(t, "value1", target["KEY1"])
	assert.Equal(t, "", target["KEY2"])
	assert.Equal(t, "another value", target["KEY3"])
	assert.Equal(t, "", target["KEY_UNQUOTED"])
	assert.Equal(t, "", target["KEY_UNQUOTED_SPACE"])
	assert.Equal(t, "", target["KEY_EMPTY"])
	assert.Equal(t, "final", target["KEY_OVERWRITE"])
	assert.Equal(t, "", target["KEY_NO_COMMENT"])
	assert.Equal(t, "", target["KEY.WITH.DOTS"])
	_, exists := target["# This is a comment line"]
	assert.False(t, exists)
}

func TestResolveValue(t *testing.T) {
	context := map[string]string{
		"NAME":     "GoLang",
		"VERSION":  "1.21",
		"PROJECT":  "ConfigLoader",
		"FULLNAME": "${PROJECT} v${VERSION}",
		"GREETING": "Hello, $NAME!",
		"SELF":     "${SELF}", // Circular, should not expand indefinitely
		"A":        "${B}",
		"B":        "${C}",
		"C":        "resolved_c",
	}

	assert.Equal(t, "GoLang", resolveValue("${NAME}", context))
	assert.Equal(t, "Project: ConfigLoader", resolveValue("Project: ${PROJECT}", context))
	assert.Equal(t, "ConfigLoader v1.21", resolveValue("${FULLNAME}", context))
	assert.Equal(t, "Hello, GoLang!", resolveValue("$GREETING", context))
	assert.Equal(t, "Hello, GoLang!", resolveValue("Hello, $NAME!", context))
	assert.Equal(t, "Value: GoLang", resolveValue("Value: $NAME", context))
	assert.Equal(t, "NoVar: $UNDEFINED", resolveValue("NoVar: $UNDEFINED", context))
	assert.Equal(t, "${SELF}", resolveValue("${SELF}", context))
	assert.Equal(t, "resolved_c", resolveValue("${A}", context))
	assert.Equal(t, "Path: /opt/app-GoLang", resolveValue("Path: /opt/app-$NAME", context))
	assert.Equal(t, "http://${SERVER_HOST}:${SERVER_PORT}/api", resolveValue("http://${SERVER_HOST}:${SERVER_PORT}/api", context))
}

func TestLoadWithDefaults_SingleEnv(t *testing.T) {
	tempDir := t.TempDir()
	createTempConfFile(t, tempDir, "install.conf", "MAIN_VAR=main_val\nNAMESPACE=global")
	confDir := filepath.Join(tempDir, "conf")
	require.NoError(t, os.Mkdir(confDir, 0755))
	createTempConfFile(t, confDir, "app.conf", "APP_VAR=app_val\nNAMESPACE=app_specific")

	lc, err := LoadWithDefaults(tempDir, "", true)
	require.NoError(t, err)
	require.NotNil(t, lc)

	assert.Equal(t, "main_val", lc.Main["MAIN_VAR"])
	assert.Equal(t, "app_val", lc.Main["APP_VAR"])
	assert.Equal(t, "app_specific", lc.Main["NAMESPACE"])
	assert.Contains(t, lc.Metadata["source_base_path"], tempDir)
	assert.Equal(t, "", lc.Metadata["source_environment_specified"])
}

func TestLoadWithDefaults_MultiEnv(t *testing.T) {
	tempDir := t.TempDir()
	createTempConfFile(t, tempDir, "install-dev.conf", "MODE=development\nAPI_URL=${DEV_API_URL}")
	createTempConfFile(t, tempDir, "install.conf", "MODE=generic")

	confDevDir := filepath.Join(tempDir, "conf-dev")
	require.NoError(t, os.Mkdir(confDevDir, 0755))
	createTempConfFile(t, confDevDir, "db.conf", "DEV_API_URL=http://dev.api\nDB_HOST=devdb")

	lc, err := LoadWithDefaults(tempDir, "dev", true)
	require.NoError(t, err)
	require.NotNil(t, lc)

	assert.Equal(t, "development", lc.Main["MODE"])
	assert.Equal(t, "http://dev.api", lc.Main["API_URL"])
	assert.Equal(t, "devdb", lc.Main["DB_HOST"])
	assert.Equal(t, "dev", lc.Metadata["source_environment_specified"])
	assert.True(t, strings.HasSuffix(lc.Metadata["discovered_primary_config_path"].(string), "install-dev.conf"))
}

func TestLoad_CustomFilePaths(t *testing.T) {
	tempDir := t.TempDir()
	file1 := createTempConfFile(t, tempDir, "custom1.conf", "VAR1=val1\nSHARED=from_custom1")
	customSubDir := filepath.Join(tempDir, "subdir")
	require.NoError(t, os.Mkdir(customSubDir, 0755))
	// file2 := createTempConfFile(t, customSubDir, "custom2.conf", "VAR2=val2\nSHARED=from_custom2_in_subdir")

	opts := Options{
		BasePath:               tempDir,
		CustomFilePaths:        []string{file1, customSubDir},
		EnableDatabaseGrouping: true,
	}
	lc, err := Load(opts)
	require.NoError(t, err)
	require.NotNil(t, lc)

	assert.Equal(t, "val1", lc.Main["VAR1"])
	assert.Equal(t, "", lc.Main["VAR2"])
	assert.Equal(t, "from_custom1", lc.Main["SHARED"])
	assert.Equal(t, "custom_paths", lc.Metadata["source_type"])
}

func TestLoad_DatabaseGrouping(t *testing.T) {
	tempDir := t.TempDir()
	createTempConfFile(t, tempDir, "install.conf", "RDBMS_DB_CLIENT=mysql\nMAIN_SETTING=abc")
	confDir := filepath.Join(tempDir, "conf")
	require.NoError(t, os.Mkdir(confDir, 0755))
	createTempConfFile(t, confDir, "database_mysql.conf", "MYSQL_HOST=mysqlserver\nDB_USER=${DB_COMMON_USER}")
	createTempConfFile(t, confDir, "database_postgres.conf", "PG_HOST=pgserver\nDB_USER=pg_user_override")
	createTempConfFile(t, confDir, "common.conf", "DB_COMMON_USER=common_db_user")

	optsEnabled := Options{BasePath: tempDir, EnableDatabaseGrouping: true}
	lcEnabled, errEnabled := Load(optsEnabled)
	require.NoError(t, errEnabled)
	require.NotNil(t, lcEnabled)

	assert.Equal(t, "abc", lcEnabled.Main["MAIN_SETTING"])
	assert.Equal(t, "mysql", lcEnabled.Main["RDBMS_DB_CLIENT"])
	assert.Equal(t, "common_db_user", lcEnabled.Main["DB_COMMON_USER"])
	require.NotNil(t, lcEnabled.DatabaseConfigs["mysql"])
	assert.Equal(t, "mysqlserver", lcEnabled.DatabaseConfigs["mysql"]["MYSQL_HOST"])
	assert.Equal(t, "common_db_user", lcEnabled.DatabaseConfigs["mysql"]["DB_USER"])
	require.NotNil(t, lcEnabled.DatabaseConfigs["postgres"])
	assert.Equal(t, "pgserver", lcEnabled.DatabaseConfigs["postgres"]["PG_HOST"])
	assert.Equal(t, "pg_user_override", lcEnabled.DatabaseConfigs["postgres"]["DB_USER"])
	_, exists := lcEnabled.Main["MYSQL_HOST"]
	assert.False(t, exists)

	optsDisabled := Options{BasePath: tempDir, EnableDatabaseGrouping: false}
	lcDisabled, errDisabled := Load(optsDisabled)
	require.NoError(t, errDisabled)
	require.NotNil(t, lcDisabled)

	assert.Equal(t, "abc", lcDisabled.Main["MAIN_SETTING"])
	assert.Equal(t, "mysql", lcDisabled.Main["RDBMS_DB_CLIENT"])
	assert.Equal(t, "common_db_user", lcDisabled.Main["DB_COMMON_USER"])
	assert.Equal(t, "mysqlserver", lcDisabled.Main["MYSQL_HOST"])
	assert.Equal(t, "pgserver", lcDisabled.Main["PG_HOST"])
	assert.Equal(t, "pg_user_override", lcDisabled.Main["DB_USER"])
	assert.Empty(t, lcDisabled.DatabaseConfigs)
}

func TestLoadedConfig_OutputFormats(t *testing.T) {
	lc := &LoadedConfig{
		Main:               map[string]string{"keyM": "valM", "shared": "main_shared"},
		DatabaseConfigs:    map[string]map[string]string{"typeA": {"keyA": "valA", "shared": "db_shared"}},
		Metadata:           map[string]interface{}{"source": "test"},
		opts:               Options{EnableDatabaseGrouping: true},
		rawMainConfig:      nil,
		rawDatabaseConfigs: nil,
	}

	jsonStr, err := lc.ToJSON()
	require.NoError(t, err)
	assert.Contains(t, jsonStr, `"keyM": "valM"`)
	assert.Contains(t, jsonStr, `"database_configs":`)
	assert.Contains(t, jsonStr, `"typeA":`)
	assert.Contains(t, jsonStr, `"keyA": "valA"`)
	assert.Contains(t, jsonStr, `"metadata":`)

	mapOutput := lc.ToMap()
	mainMap, ok := mapOutput["main"].(map[string]string)
	assert.True(t, ok)
	assert.Equal(t, "valM", mainMap["keyM"])

	dbConfigsMap, ok := mapOutput["database_configs"].(map[string]map[string]string)
	assert.True(t, ok)
	typeAMap, ok := dbConfigsMap["typeA"]
	assert.True(t, ok)
	assert.Equal(t, "valA", typeAMap["keyA"])

	lc.opts.EnableDatabaseGrouping = false
	lc.DatabaseConfigs = nil
	mapNoDb := lc.ToMap()
	_, hasDb := mapNoDb["database_configs"]
	assert.False(t, hasDb)
}
