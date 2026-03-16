package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Install Claude Code hooks into your settings",
	Long:  `Adds ClauGuard hooks to ~/.claude/settings.json so Claude Code automatically scans dependencies on manifest edits and before commits.`,
	RunE:  runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("could not determine home directory: %w", err)
	}

	settingsPath := filepath.Join(homeDir, ".claude", "settings.json")

	// Read existing settings.
	var settings map[string]any
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Create .claude dir if needed.
			if mkErr := os.MkdirAll(filepath.Join(homeDir, ".claude"), 0o755); mkErr != nil {
				return fmt.Errorf("could not create ~/.claude: %w", mkErr)
			}
			settings = make(map[string]any)
		} else {
			return fmt.Errorf("could not read %s: %w", settingsPath, err)
		}
	} else {
		if err := json.Unmarshal(data, &settings); err != nil {
			return fmt.Errorf("could not parse %s: %w", settingsPath, err)
		}
	}

	// Resolve the clauguard binary path.
	binPath, err := os.Executable()
	if err != nil {
		binPath = "clauguard" // fallback to PATH lookup
	}

	// Build the hooks config.
	clauguardHooks := map[string]any{
		"PostToolUse": []any{
			map[string]any{
				"matcher": "Edit|Write",
				"hooks": []any{
					map[string]any{
						"type":    "command",
						"command": binPath + " hook post-edit",
					},
				},
			},
		},
		"PreToolUse": []any{
			map[string]any{
				"matcher": "Bash(git commit:*)",
				"hooks": []any{
					map[string]any{
						"type":    "command",
						"command": binPath + " hook pre-commit",
					},
				},
			},
		},
	}

	// Merge into existing hooks (don't overwrite user's other hooks).
	existingHooks, _ := settings["hooks"].(map[string]any)
	if existingHooks == nil {
		existingHooks = make(map[string]any)
	}

	for event, hookList := range clauguardHooks {
		existing, _ := existingHooks[event].([]any)
		existingHooks[event] = append(existing, hookList.([]any)...)
	}
	settings["hooks"] = existingHooks

	// Write back.
	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("could not encode settings: %w", err)
	}

	if err := os.WriteFile(settingsPath, out, 0o644); err != nil {
		return fmt.Errorf("could not write %s: %w", settingsPath, err)
	}

	fmt.Println("ClauGuard hooks installed into", settingsPath)
	fmt.Println()
	fmt.Println("Active hooks:")
	fmt.Println("  PostToolUse (Edit|Write)     → scans after dependency manifest edits")
	fmt.Println("  PreToolUse  (git commit)     → blocks commits with critical issues")
	fmt.Println()
	fmt.Println("To remove, edit", settingsPath, "and delete the clauguard hook entries.")

	return nil
}
