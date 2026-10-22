package tui

import (
	"github.com/stunndard/cocosmail/core"
	"github.com/unxed/vtinput"
	"github.com/unxed/vtui"
)

// listEditor edits a setting holding a list, one item per table row, with its
// own key bar. What an item is, how it's shown, stored and edited comes from
// the specific editors: listeners (DsnEditor), local IPs (LocalIpsEditor).
type listEditor[T any] struct {
	*vtui.Window
	ed     *Editor
	key    string
	noun   string // one item, in messages: "listener"
	nouns  string // items: "listeners"
	items  []T
	orig   string
	table  *vtui.Table
	help   [2]*vtui.Text
	x1, y1 int
	x2, y2 int

	// value is the setting value of items
	value func(items []T) string
	// cell is the text of column col of item
	cell    func(item T, col int) string
	newItem func() T
	// dialog edits item, calling done with it on Ok
	dialog func(item T, isNew bool, done func(T)) *formWindow
	// helpText is shown under the table
	helpText func() string
	// optional: check before apply, title suffix, more keys
	check       func(items []T) error
	titleSuffix func() string
	extraKey    func(e *vtinput.InputEvent) bool
	extraLabels map[int][2]string
	extraHelp   [][2]string
}

type listRow[T any] struct {
	le   *listEditor[T]
	item T
}

// GetCellText implements vtui.TableRow
func (r listRow[T]) GetCellText(col int) string {
	return r.le.cell(r.item, col)
}

// newListEditor returns a list editor of setting key over ed, the specific
// editor sets the functions and the items, then calls refresh
func newListEditor[T any](ed *Editor, key, noun, nouns string, columns []vtui.TableColumn) *listEditor[T] {
	le := &listEditor[T]{ed: ed, key: key, noun: noun, nouns: nouns, orig: ed.values[key]}
	le.x1, le.y1, le.x2, le.y2 = 3, 2, ed.width-4, ed.height-4
	le.Window = vtui.NewDialog(le.x1, le.y1, le.x2, le.y2, " "+core.SettingEnvName(key)+" ")
	le.table = vtui.NewTable(le.x1+2, le.y1+2, le.x2-le.x1-3, le.y2-le.y1-6, columns)
	le.table.ShowHeader = true
	le.table.SetPosition(le.x1+2, le.y1+2, le.x2-2, le.y2-5)
	le.table.OnAction = func(int) { le.editRow(false) }
	le.AddItem(le.table)
	for i := range le.help {
		y := le.y2 - 3 + i
		le.help[i] = vtui.NewText(le.x1+2, y, "", 0)
		le.help[i].SetPosition(le.x1+2, y, le.x2-2, y)
		le.AddItem(le.help[i])
	}
	return le
}

// refresh shows items, title and help text again
func (le *listEditor[T]) refresh() {
	rows := make([]vtui.TableRow, len(le.items))
	for i, item := range le.items {
		rows[i] = listRow[T]{le, item}
	}
	le.table.SetRows(rows)
	if le.table.SelectPos >= len(le.items) {
		le.table.SelectPos = len(le.items) - 1
	}
	if le.table.SelectPos < 0 {
		le.table.SelectPos = 0
	}
	title := " " + core.SettingEnvName(le.key)
	if le.titleSuffix != nil {
		title += ": " + le.titleSuffix()
	}
	title += " "
	if le.value(le.items) != le.orig {
		title += "(changed) "
	}
	le.SetTitle(title)
	lines := wrap(le.helpText(), le.x2-le.x1-4)
	for i, t := range le.help {
		text := ""
		if i < len(lines) {
			text = lines[i]
		}
		t.SetText(literal(text))
	}
}

// GetKeyLabels replace the key bar of the main window
func (le *listEditor[T]) GetKeyLabels() *vtui.KeySet {
	labels := map[int][2]string{
		1: {"Help", "Help"}, 2: {"Apply", "Ok"}, 4: {"Edit", "Edit"}, 5: {"Copy", "Copy"},
		7: {"New", "New"}, 8: {"Delete", "Del"}, 10: {"Close", "End"},
	}
	for n, l := range le.extraLabels {
		labels[n] = l
	}
	return keyLabels(le.ed.width, labels)
}

// helpKeys are shown by the help dialog
func (le *listEditor[T]) helpKeys() [][2]string {
	keys := [][2]string{
		{"F2", "Apply the " + le.nouns + " to the setting and close"},
		{"F4, Enter", "Edit the selected " + le.noun},
		{"F5", "Copy the selected " + le.noun},
		{"F7, Ins", "Add a " + le.noun},
		{"F8, Del", "Delete the selected " + le.noun},
		{"Ctrl+Up/Down", "Move the selected " + le.noun},
	}
	keys = append(keys, le.extraHelp...)
	return append(keys, [2]string{"F10, Esc", "Close without applying, asks if changed"})
}

// ProcessKey handles the function keys, other keys go to the table
func (le *listEditor[T]) ProcessKey(e *vtinput.InputEvent) bool {
	if !e.KeyDown {
		return le.Window.ProcessKey(e)
	}
	if le.extraKey != nil && le.extraKey(e) {
		return true
	}
	ctrl := e.ControlKeyState&(vtinput.LeftCtrlPressed|vtinput.RightCtrlPressed) != 0
	switch {
	case ctrl && e.VirtualKeyCode == vtinput.VK_UP:
		le.moveRow(-1)
	case ctrl && e.VirtualKeyCode == vtinput.VK_DOWN:
		le.moveRow(1)
	case e.VirtualKeyCode == vtinput.VK_F1:
		vtui.FrameManager.Push(helpDialog(le.ed, le.helpKeys()))
	case e.VirtualKeyCode == vtinput.VK_F2:
		le.apply()
	case e.VirtualKeyCode == vtinput.VK_F4:
		le.editRow(false)
	case e.VirtualKeyCode == vtinput.VK_F5:
		if len(le.items) > 0 {
			le.items = append(le.items, le.items[le.table.SelectPos])
			le.table.SelectPos = len(le.items) - 1
			le.refresh()
		}
	case e.VirtualKeyCode == vtinput.VK_F7, e.VirtualKeyCode == vtinput.VK_INSERT:
		le.editRow(true)
	case e.VirtualKeyCode == vtinput.VK_F8, e.VirtualKeyCode == vtinput.VK_DELETE:
		le.deleteRow()
	case e.VirtualKeyCode == vtinput.VK_F10, e.VirtualKeyCode == vtinput.VK_ESCAPE:
		le.cancel()
	default:
		return le.Window.ProcessKey(e)
	}
	return true
}

// moveRow moves the selected item by d rows
func (le *listEditor[T]) moveRow(d int) {
	i, j := le.table.SelectPos, le.table.SelectPos+d
	if i < 0 || j < 0 || j >= len(le.items) {
		return
	}
	le.items[i], le.items[j] = le.items[j], le.items[i]
	le.table.SelectPos = j
	le.refresh()
}

func (le *listEditor[T]) deleteRow() {
	if len(le.items) == 0 {
		return
	}
	i := le.table.SelectPos
	text := "Delete " + le.noun + " " + le.value(le.items[i:i+1]) + "?"
	dlg := vtui.ShowMessage("Delete", literal(text), []string{"&Delete", "&Cancel"})
	dlg.OnResult = func(code int) {
		if code == 0 {
			le.items = append(le.items[:i], le.items[i+1:]...)
			le.refresh()
		}
	}
}

// editRow edits the selected item, or a new one
func (le *listEditor[T]) editRow(isNew bool) {
	if !isNew && len(le.items) == 0 {
		isNew = true
	}
	item := le.newItem()
	if !isNew {
		item = le.items[le.table.SelectPos]
	}
	vtui.FrameManager.Push(le.dialog(item, isNew, func(ni T) {
		if isNew {
			le.items = append(le.items, ni)
			le.table.SelectPos = len(le.items) - 1
		} else {
			le.items[le.table.SelectPos] = ni
		}
		le.refresh()
	}))
}

// apply sets the items in the main editor and closes
func (le *listEditor[T]) apply() {
	if le.check != nil {
		if err := le.check(le.items); err != nil {
			le.ed.message("Error", err.Error())
			return
		}
	}
	v := le.value(le.items)
	if err := core.ValidateSetting(le.key, v); err != nil {
		le.ed.message("Error", err.Error())
		return
	}
	le.ed.set(le.key, v)
	le.SetExitCode(1)
}

func (le *listEditor[T]) cancel() {
	if le.value(le.items) == le.orig {
		le.SetExitCode(-1)
		return
	}
	dlg := vtui.ShowMessage("Cancel", "The "+le.nouns+" were changed.", []string{"&Apply", "&Discard", "&Cancel"})
	dlg.OnResult = func(code int) {
		switch code {
		case 0:
			le.apply()
		case 1:
			le.SetExitCode(-1)
		}
	}
}

// itemDialog returns a form dialog over the list editor, see formDialog
func (le *listEditor[T]) itemDialog(title string, fields []itemField, checks []itemCheck, ok func(values []string, checked []bool) error) *formWindow {
	return formDialog(le.ed, title, fields, checks, ok)
}
