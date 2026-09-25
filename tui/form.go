package tui

import (
	"github.com/unxed/vtinput"
	"github.com/unxed/vtui"
)

// formWindow is a dialog of fields. F3 shows or hides its secret fields,
// like F3 in the editor, whose key labels don't apply in the dialog.
type formWindow struct {
	*vtui.Window
	ed      *Editor
	secrets []*vtui.Edit
}

// ProcessKey handles F3, other keys go to the dialog
func (f *formWindow) ProcessKey(e *vtinput.InputEvent) bool {
	if e.KeyDown && e.VirtualKeyCode == vtinput.VK_F3 {
		if len(f.secrets) > 0 {
			f.ed.secrets = !f.ed.secrets
			f.showSecrets()
		}
		return true
	}
	return f.Window.ProcessKey(e)
}

// showSecrets masks secret fields, unless secrets are shown
func (f *formWindow) showSecrets() {
	for _, e := range f.secrets {
		e.PasswordMode = !f.ed.secrets
	}
}

// GetKeyLabels are the key bar labels: F3 if there are secret fields
func (f *formWindow) GetKeyLabels() *vtui.KeySet {
	labels := map[int][2]string{}
	if len(f.secrets) > 0 {
		labels[3] = secretsLabel(f.ed.secrets)
	}
	return keyLabels(f.ed.width, labels)
}

// newFormWindow wraps dialog dlg, secrets are its secret fields
func newFormWindow(ed *Editor, dlg *vtui.Window, secrets ...*vtui.Edit) *formWindow {
	f := &formWindow{Window: dlg, ed: ed, secrets: secrets}
	f.showSecrets()
	return f
}

// itemField is a text field of formDialog
type itemField struct {
	label string
	value string
	hint  string
	width int // 0: as wide as possible
	// secret: hidden, unless secrets are shown (F3)
	secret bool
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
func formDialog(ed *Editor, title string, fields []itemField, checks []itemCheck, ok func(values []string, checked []bool) error) *formWindow {
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
	var secrets []*vtui.Edit
	for i, f := range fields {
		width := f.width
		if width == 0 {
			width = fieldW
		}
		edits[i] = newEdit(ex, y, width, f.value)
		if f.secret {
			secrets = append(secrets, edits[i])
		}
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
	return newFormWindow(ed, dlg, secrets...)
}
