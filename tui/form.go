package tui

import (
	"github.com/unxed/vtui"
)

// itemField is a text field of formDialog
type itemField struct {
	label string
	value string
	hint  string
	width int // 0: as wide as possible
	// password: typed text is hidden
	password bool
}

// itemCheck is a checkbox of formDialog
type itemCheck struct {
	label   string
	checked bool
}

// formDialog returns a dialog of labeled fields, then checkboxes, with Ok and
// Cancel. ok is called with the field values and the checkbox states: the
// dialog closes if it returns nil, else the error is shown. Fields are
// separated by an empty line, unless the screen is too small for it.
func formDialog(ed *Editor, title string, fields []itemField, checks []itemCheck, ok func(values []string, checked []bool) error) *vtui.Window {
	const labelW = 13
	w := 64
	if w > ed.width-4 {
		w = ed.width - 4
	}
	fieldW := w - labelW - 5
	hints := make([][]string, len(fields))
	for i, f := range fields {
		hints[i] = wrap(f.hint, fieldW)
	}
	// borders, air, buttons
	lines := func(gap int) int {
		h := 6
		for i := range fields {
			h += 1 + gap + len(hints[i])
		}
		if len(checks) > 0 {
			h += len(checks) + 1
		}
		return h
	}
	gap := 1
	if lines(1) > ed.height-2 {
		gap = 0
	}
	h := lines(gap)
	x1, y1 := (ed.width-w)/2, (ed.height-1-h)/2
	if y1 < 0 {
		y1 = 0
	}
	dlg := vtui.NewDialog(x1, y1, x1+w-1, y1+h-1, title)
	x, ex, y := x1+2, x1+2+labelW+1, y1+2
	edits := make([]*vtui.Edit, len(fields))
	for i, f := range fields {
		width := f.width
		if width == 0 {
			width = fieldW
		}
		edits[i] = newEdit(ex, y, width, f.value)
		edits[i].PasswordMode = f.password
		dlg.AddItem(vtui.NewLabel(x, y, f.label, edits[i]))
		dlg.AddItem(edits[i])
		y++
		for _, l := range hints[i] {
			dlg.AddItem(vtui.NewText(ex, y, literal(l), 0))
			y++
		}
		y += gap
	}
	boxes := make([]*vtui.Checkbox, len(checks))
	for i, c := range checks {
		boxes[i] = vtui.NewCheckbox(ex, y, c.label, false)
		if c.checked {
			boxes[i].State = 1
		}
		dlg.AddItem(boxes[i])
		y++
	}
	okBtn := vtui.NewButton(0, 0, "&Ok")
	okBtn.IsDefault = true
	cancel := vtui.NewButton(0, 0, "&Cancel")
	by := y1 + h - 3
	okBtn.SetPosition(x1+w/2-12, by, x1+w/2-12+okBtn.X2-okBtn.X1, by)
	cancel.SetPosition(x1+w/2+2, by, x1+w/2+2+cancel.X2-cancel.X1, by)
	okBtn.OnClick = func() {
		values := make([]string, len(edits))
		for i, e := range edits {
			values[i] = e.GetText()
		}
		checked := make([]bool, len(boxes))
		for i, b := range boxes {
			checked[i] = b.State == 1
		}
		if err := ok(values, checked); err != nil {
			ed.message("Error", err.Error())
			return
		}
		dlg.SetExitCode(1)
	}
	cancel.OnClick = func() { dlg.SetExitCode(-1) }
	dlg.AddItem(okBtn)
	dlg.AddItem(cancel)
	return dlg
}
