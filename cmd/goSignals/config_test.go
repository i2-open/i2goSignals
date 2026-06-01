package main

import (
    "path/filepath"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// TestCheckConfigPath_GosignalsHomeDir verifies that when GOSIGNALS_HOME points
// at a directory, config.json and credentials.json co-locate in that same
// directory (GH #143 — credentials.json must not land one level above
// config.json).
func TestCheckConfigPath_GosignalsHomeDir(t *testing.T) {
    home := t.TempDir()
    t.Setenv("GOSIGNALS_HOME", home)

    g := &Globals{} // g.Config empty -> resolve from env
    c := &ConfigData{}
    require.NoError(t, c.checkConfigPath(g))

    // config.json should live directly inside the GOSIGNALS_HOME directory.
    assert.Equal(t, filepath.Join(home, ConfigFile), g.ConfigFile,
        "config.json should resolve inside GOSIGNALS_HOME directory")

    // credentials.json must co-locate in the same directory as config.json.
    assert.Equal(t, filepath.Dir(g.ConfigFile), filepath.Dir(credentialsPath(g)),
        "config.json and credentials.json must resolve to the same directory")
    assert.Equal(t, home, filepath.Dir(credentialsPath(g)),
        "credentials.json should live inside GOSIGNALS_HOME directory")
}

// TestCheckConfigPath_GosignalsHomeFile verifies the regression guard: when
// GOSIGNALS_HOME is a file path, credentials.json co-locates in that file's
// directory (existing behavior preserved).
func TestCheckConfigPath_GosignalsHomeFile(t *testing.T) {
    dir := t.TempDir()
    configFile := filepath.Join(dir, "toolconfig.json")
    t.Setenv("GOSIGNALS_HOME", configFile)

    g := &Globals{}
    c := &ConfigData{}
    require.NoError(t, c.checkConfigPath(g))

    assert.Equal(t, configFile, g.ConfigFile,
        "a file-valued GOSIGNALS_HOME should be used verbatim as the config file")
    assert.Equal(t, dir, filepath.Dir(credentialsPath(g)),
        "credentials.json should co-locate in the config file's directory")
}
