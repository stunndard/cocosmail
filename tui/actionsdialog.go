package tui

import (
	"strings"

	"github.com/stunndard/cocosmail/core"
	"github.com/unxed/vtui"
)

// actionChoices are the actions for a result of a check
var actionChoices = []string{"accept", "reject"}

// parseActions splits a value of n actions separated by :. A missing or
// unknown action is accept, fixed when saved.
func parseActions(value string, n int) []string {
	parts := strings.Split(value, ":")
	actions := make([]string, n)
	for i := range actions {
		actions[i] = "accept"
		if i < len(parts) && strings.TrimSpace(parts[i]) == "reject" {
			actions[i] = "reject"
		}
	}
	return actions
}

// actionsDialog returns a dialog to choose accept or reject for each result
// of s.Actions, in a list each
func (ed *Editor) actionsDialog(s core.Setting) *formWindow {
	w := ed.width - 8
	if w > 76 {
		w = 76
	}
	textLines := wrap(s.Description, w-4)
	h := len(textLines) + len(s.Actions) + 9
	x1, y1 := (ed.width-w)/2, (ed.height-1-h)/2
	dlg := vtui.NewDialog(x1, y1, x1+w-1, y1+h-1, " "+core.SettingEnvName(s.Key)+" ")
	for i, l := range textLines {
		dlg.AddItem(vtui.NewText(x1+2, y1+2+i, literal(l), 0))
	}

	labelW := 0
	for _, r := range s.Actions {
		if len(r) > labelW {
			labelW = len(r)
		}
	}
	current := parseActions(ed.values[s.Key], len(s.Actions))
	boxes := make([]*vtui.ComboBox, len(s.Actions))
	y := y1 + 2 + len(textLines) + 1
	for i, r := range s.Actions {
		dlg.AddItem(vtui.NewText(x1+4, y, literal(r), 0))
		cb := vtui.NewComboBox(x1+4+labelW+2, y, 12, actionChoices)
		cb.DropdownOnly = true
		cb.Edit.SetText(current[i])
		dlg.AddItem(cb)
		boxes[i] = cb
		y++
	}
	dlg.AddItem(vtui.NewText(x1+2, y+1, literal("Ctrl+Down or a click opens a list, Tab goes to the next one"), 0))

	y += 3
	ok := vtui.NewButton(0, y, "&Ok")
	ok.IsDefault = true
	cancel := vtui.NewButton(0, y, "&Cancel")
	ok.SetPosition(x1+w/2-12, y, x1+w/2-12+ok.X2-ok.X1, y)
	cancel.SetPosition(x1+w/2+2, y, x1+w/2+2+cancel.X2-cancel.X1, y)
	ok.OnClick = func() {
		actions := make([]string, len(boxes))
		for i, cb := range boxes {
			actions[i] = cb.Edit.GetText()
		}
		v := strings.Join(actions, ":")
		if err := core.ValidateSetting(s.Key, v); err != nil {
			ed.message("Error", err.Error())
			return
		}
		ed.set(s.Key, v)
		dlg.SetExitCode(1)
	}
	cancel.OnClick = func() { dlg.SetExitCode(-1) }
	dlg.AddItem(ok)
	dlg.AddItem(cancel)
	return newFormWindow(ed, dlg)
}
