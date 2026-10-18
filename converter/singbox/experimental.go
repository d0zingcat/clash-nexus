package singbox

import (
	"strings"

	"clash-nexus/converter/clash"
)

func (b *builder) buildExperimental() map[string]interface{} {
	controller := strings.TrimSpace(clash.MapGetStr(b.config, "external-controller", ""))
	if controller == "" {
		return nil
	}
	api := map[string]interface{}{
		"external_controller": controller,
	}
	if secret := clash.MapGetStr(b.config, "secret", ""); secret != "" {
		api["secret"] = secret
	}
	if mode := strings.ToLower(strings.TrimSpace(clash.MapGetStr(b.config, "mode", ""))); mode != "" {
		api["default_mode"] = mode
	}
	if ui := strings.TrimSpace(clash.MapGetStr(b.config, "external-ui", "")); ui != "" {
		if strings.HasPrefix(ui, "http://") || strings.HasPrefix(ui, "https://") {
			api["external_ui_download_url"] = ui
		} else {
			api["external_ui"] = ui
		}
	}
	if ui := strings.TrimSpace(clash.MapGetStr(b.config, "external-ui-url", "")); ui != "" {
		api["external_ui_download_url"] = ui
	}
	return map[string]interface{}{"clash_api": api}
}
