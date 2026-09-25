// Package tui is the text UI configurator of cocosmail, built on vtui.
package tui

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/stunndard/cocosmail/core"
	"github.com/unxed/vtinput"
	"github.com/unxed/vtui"
	"golang.org/x/term"
)

const secretMask = "********"

// descLines is the number of lines describing the selected setting
const descLines = 3

// Editor is the configurator window: a table of all settings, the
// description of the selected one and a key bar
type Editor struct {
	*vtui.Window
	store   Store
	values  map[string]string // being edited
	saved   map[string]string // as loaded or last saved
	sources map[string]string
	rows    []settingRow
	table   *vtui.Table
	desc    [descLines]*vtui.Text
	width   int
	height  int
	secrets bool
	// Quit is called when the user quits
	Quit func()
	// Err is the last save error, if any
	Err error
}

// settingRow is a table row: a setting, or a section title if key is empty
type settingRow struct {
	ed      *Editor
	key     string
	section string
}

// GetCellText implements vtui.TableRow
func (r settingRow) GetCellText(col int) string {
	if r.key == "" {
		if col == 0 {
			return "[" + r.section + "]"
		}
		return ""
	}
	switch col {
	case 0:
		return r.key
	case 1:
		return r.ed.displayValue(r.key)
	default:
		source := r.ed.sources[r.key]
		if r.ed.values[r.key] != r.ed.saved[r.key] {
			source = "changed"
		}
		return source
	}
}

// NewEditor builds the configurator window for a screen of width x height,
// the last line is left for the key bar
func NewEditor(store Store, width, height int) (*Editor, error) {
	values, sources, err := store.Load()
	if err != nil {
		return nil, err
	}
	ed := &Editor{
		store:   store,
		values:  values,
		saved:   copyValues(values),
		sources: sources,
	}
	ed.Window = vtui.NewWindow(0, 0, width-1, height-2, "")
	section := ""
	for _, s := range core.Settings {
		if s.Section != section {
			section = s.Section
			ed.rows = append(ed.rows, settingRow{ed: ed, section: section})
		}
		ed.rows = append(ed.rows, settingRow{ed: ed, key: s.Key, section: s.Section})
	}
	ed.table = vtui.NewTable(0, 0, 10, 5, []vtui.TableColumn{
		{Title: "Setting", Width: 34},
		{Title: "Value", Width: 0, MinWidth: 10},
		{Title: "Source", Width: 8},
	})
	ed.table.ShowHeader = true
	ed.table.QuickSearch = true
	rows := make([]vtui.TableRow, len(ed.rows))
	for i, r := range ed.rows {
		rows[i] = r
	}
	ed.table.SetRows(rows)
	ed.table.OnSelect = func(int) { ed.updateDescription() }
	ed.table.OnSearchChange = func(string) { ed.updateDescription() }
	ed.table.OnAction = func(int) { ed.edit() }
	ed.AddItem(ed.table)
	for i := range ed.desc {
		ed.desc[i] = vtui.NewText(0, 0, "", 0)
		ed.AddItem(ed.desc[i])
	}
	ed.layout(width, height)
	// first setting, not the section title
	ed.table.SelectPos = 1
	ed.updateDescription()
	ed.updateTitle()
	return ed, nil
}

// layout places the elements for a screen of width x height
func (ed *Editor) layout(width, height int) {
	ed.width, ed.height = width, height
	ed.Window.SetPosition(0, 0, width-1, height-2)
	bottom := height - 4 // last line inside the frame, with one line of air
	ed.table.SetPosition(2, 2, width-3, bottom-descLines-1)
	for i, t := range ed.desc {
		y := bottom - descLines + 1 + i
		t.SetPosition(2, y, width-3, y)
	}
}

// ResizeConsole follows the terminal size
func (ed *Editor) ResizeConsole(w, h int) {
	ed.layout(w, h)
	if vtui.FrameManager.KeyBar != nil {
		vtui.FrameManager.KeyBar.SetPosition(0, h-1, w-1, h-1)
	}
}

// GetKeyLabels are the key bar labels
func (ed *Editor) GetKeyLabels() *vtui.KeySet {
	ks := &vtui.KeySet{}
	ks.Normal = vtui.KeyBarLabels{"", "Save", "Secret", "Edit", "", "", "", "Reset", "", "Quit", "", ""}
	return ks
}

// ProcessKey handles the function keys, other keys go to the table
func (ed *Editor) ProcessKey(e *vtinput.InputEvent) bool {
	if e.KeyDown {
		switch e.VirtualKeyCode {
		case vtinput.VK_F2:
			ed.save()
			return true
		case vtinput.VK_F3:
			ed.secrets = !ed.secrets
			return true
		case vtinput.VK_F4:
			ed.edit()
			return true
		case vtinput.VK_F8:
			ed.reset()
			return true
		case vtinput.VK_F10, vtinput.VK_ESCAPE:
			// Esc clears a quick search first
			if e.VirtualKeyCode == vtinput.VK_ESCAPE && ed.table.SearchText() != "" {
				break
			}
			ed.quit()
			return true
		}
	}
	return ed.Window.ProcessKey(e)
}

// selected returns the key of the selected setting, "" on a section title
func (ed *Editor) selected() string {
	pos := ed.table.SelectPos
	if ed.table.RowAt(pos) >= 0 {
		pos = ed.table.RowAt(pos)
	}
	if pos < 0 || pos >= len(ed.rows) {
		return ""
	}
	return ed.rows[pos].key
}

func (ed *Editor) displayValue(key string) string {
	s, _ := core.SettingByKey(key)
	v := ed.values[key]
	if s.Secret && v != "" && v != s.Default && !ed.secrets {
		return secretMask
	}
	return v
}

func (ed *Editor) changed() map[string]string {
	changed := make(map[string]string)
	for k, v := range ed.values {
		if ed.saved[k] != v {
			changed[k] = v
		}
	}
	return changed
}

func (ed *Editor) updateTitle() {
	title := " cocosmail settings: " + ed.store.Title() + " "
	if n := len(ed.changed()); n > 0 {
		title = fmt.Sprintf("%s(%d changed) ", title, n)
	}
	ed.SetTitle(title)
}

func (ed *Editor) updateDescription() {
	lines := make([]string, descLines)
	key := ed.selected()
	if s, ok := core.SettingByKey(key); ok {
		text := s.Description
		switch {
		case s.Required:
			text += ". Required."
		case s.Default != "":
			text += ". Default: " + s.Default + "."
		}
		if s.Restart {
			text += " Needs a restart."
		}
		if why := ed.store.ReadOnly(key); why != "" {
			text += " Read only: " + why + "."
		}
		wrapped := wrap(text, ed.width-6)
		for i := 0; i < descLines && i < len(wrapped); i++ {
			lines[i] = wrapped[i]
		}
	}
	for i, t := range ed.desc {
		t.SetText(lines[i])
	}
}

// set changes a value being edited
func (ed *Editor) set(key, value string) {
	ed.values[key] = value
	ed.updateTitle()
}

// edit edits the selected setting: bools toggle, choices and text in a dialog
func (ed *Editor) edit() {
	key := ed.selected()
	s, ok := core.SettingByKey(key)
	if !ok {
		return
	}
	if why := ed.store.ReadOnly(key); why != "" {
		ed.message("Read only", core.SettingEnvName(key)+": "+why)
		return
	}
	if isBool(key) {
		if ed.values[key] == "true" {
			ed.set(key, "false")
		} else {
			ed.set(key, "true")
		}
		return
	}
	vtui.FrameManager.Push(ed.editDialog(*s))
}

// reset sets the selected setting back to its default
func (ed *Editor) reset() {
	key := ed.selected()
	s, ok := core.SettingByKey(key)
	if !ok || ed.store.ReadOnly(key) != "" {
		return
	}
	ed.set(key, s.Default)
}

// save checks and saves changed settings, after confirmation
func (ed *Editor) save() {
	changed := ed.changed()
	if len(changed) == 0 {
		ed.message("Save", "Nothing changed.")
		return
	}
	if errs := core.ValidateSettings(changed); len(errs) > 0 {
		ed.message("Error", errs[0].Error())
		return
	}
	for _, s := range core.Settings {
		if s.Required && ed.values[s.Key] == "" {
			ed.message("Error", core.SettingEnvName(s.Key)+" is required.")
			return
		}
	}
	keys := sortedKeys(changed)
	var text strings.Builder
	for i, k := range keys {
		if i == 8 {
			fmt.Fprintf(&text, "and %d more\n", len(keys)-8)
			break
		}
		fmt.Fprintf(&text, "%s = %s\n", k, ed.displayValue(k))
	}
	text.WriteString("\n" + ed.store.ApplyNote(keys))
	dlg := vtui.ShowMessage("Save", text.String(), []string{"&Save", "&Cancel"})
	dlg.OnResult = func(code int) {
		if code != 0 {
			return
		}
		if err := ed.store.Save(changed); err != nil {
			ed.Err = err
			ed.message("Error", "Not saved: "+err.Error())
			return
		}
		ed.Err = nil
		ed.saved = copyValues(ed.values)
		ed.updateTitle()
	}
}

// quit quits, asking what to do with unsaved changes
func (ed *Editor) quit() {
	if len(ed.changed()) == 0 {
		ed.doQuit()
		return
	}
	dlg := vtui.ShowMessage("Quit", "Settings were changed and not saved.", []string{"&Save", "&Discard", "&Cancel"})
	dlg.OnResult = func(code int) {
		switch code {
		case 0:
			ed.save()
		case 1:
			ed.doQuit()
		}
	}
}

func (ed *Editor) doQuit() {
	if ed.Quit != nil {
		ed.Quit()
	}
}

func (ed *Editor) message(title, text string) {
	vtui.ShowMessage(title, text, []string{"&Ok"})
}

// editDialog returns a dialog to edit a text value, or to choose one of s.Choices
func (ed *Editor) editDialog(s core.Setting) *vtui.Window {
	w := ed.width - 8
	if w > 76 {
		w = 76
	}
	textLines := wrap(s.Description, w-4)
	h := len(textLines) + 8
	x1, y1 := (ed.width-w)/2, (ed.height-1-h)/2
	dlg := vtui.NewDialog(x1, y1, x1+w-1, y1+h-1, " "+core.SettingEnvName(s.Key)+" ")
	for i, l := range textLines {
		dlg.AddItem(vtui.NewText(x1+2, y1+2+i, l, 0))
	}
	y := y1 + 2 + len(textLines) + 1
	var getValue func() string
	if len(s.Choices) > 0 {
		cb := vtui.NewComboBox(x1+2, y, w-4, s.Choices)
		cb.DropdownOnly = true
		cb.Edit.SetText(ed.values[s.Key])
		dlg.AddItem(cb)
		getValue = cb.Edit.GetText
	} else {
		edit := vtui.NewEdit(x1+2, y, w-4, ed.values[s.Key])
		edit.PasswordMode = s.Secret && !ed.secrets
		dlg.AddItem(edit)
		getValue = edit.GetText
	}
	ok := vtui.NewButton(0, y+2, "&Ok")
	ok.IsDefault = true
	cancel := vtui.NewButton(0, y+2, "&Cancel")
	ok.SetPosition(x1+w/2-12, y+2, x1+w/2-12+ok.X2-ok.X1, y+2)
	cancel.SetPosition(x1+w/2+2, y+2, x1+w/2+2+cancel.X2-cancel.X1, y+2)
	ok.OnClick = func() {
		v := strings.TrimSpace(getValue())
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
	return dlg
}

// Run opens the configurator on store in the terminal, until the user quits
func Run(store Store) error {
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		return errors.New("the configurator needs a terminal")
	}
	width, height, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		return err
	}
	if width < 60 || height < 15 {
		return fmt.Errorf("the terminal is too small (%dx%d), at least 60x15 is needed", width, height)
	}
	restore, err := vtui.PrepareTerminal()
	if err != nil {
		return err
	}
	if restore != nil {
		defer restore()
	}

	scr := vtui.NewScreenBuf()
	scr.AllocBuf(width, height)
	vtui.FrameManager.Init(scr)
	vtui.FrameManager.KeyBar = vtui.NewKeyBar()
	vtui.FrameManager.KeyBar.SetPosition(0, height-1, width-1, height-1)
	vtui.FrameManager.Push(vtui.NewDesktop())
	ed, err := NewEditor(store, width, height)
	if err != nil {
		return err
	}
	ed.Quit = vtui.FrameManager.Stop
	vtui.FrameManager.Push(ed)
	vtui.FrameManager.Run(vtinput.NewReader(os.Stdin, false))
	return ed.Err
}

// isBool returns true if the setting is a bool
func isBool(key string) bool {
	return core.SettingKind(key) == reflect.Bool
}

func copyValues(m map[string]string) map[string]string {
	c := make(map[string]string, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// wrap splits text in lines of at most width characters, on spaces
func wrap(text string, width int) (lines []string) {
	line := ""
	for _, word := range strings.Fields(text) {
		if line != "" && len(line)+1+len(word) > width {
			lines = append(lines, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	if line != "" {
		lines = append(lines, line)
	}
	return
}
