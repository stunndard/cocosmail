// Package tui is the text UI configurator of cocosmail, built on vtui.
package tui

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/stunndard/cocosmail/core"
	"github.com/unxed/vtinput"
	"github.com/unxed/vtui"
	"golang.org/x/term"
)

const secretMask = "********"

// descLines is the number of lines describing the selected setting
const descLines = 3

// allSettings is the last entry of the section list: all sections at once
const allSettings = "all settings"

// sectionsWidth is the width of the section list
const sectionsWidth = 15

// Editor is the configurator window: the list of sections, a table of the
// settings of the selected section, the description of the selected setting
// and a key bar. Below the settings sections, the data sections: domains,
// users... one item per table row.
type Editor struct {
	*vtui.Window
	store     Store
	values    map[string]string // being edited
	saved     map[string]string // as loaded or last saved
	sources   map[string]string
	data      *core.Data // being edited
	savedData *core.Data
	sections  *vtui.ListBox
	rows      []settingRow
	table     *vtui.Table
	columns   []vtui.TableColumn // of settings
	kind      *dataKind          // data shown, nil for settings
	desc      [descLines]*vtui.Text
	width     int
	height    int
	secrets   bool
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
	data, err := store.LoadData()
	if err != nil {
		return nil, err
	}
	ed := &Editor{
		store:     store,
		values:    values,
		saved:     copyValues(values),
		sources:   sources,
		data:      data,
		savedData: data.Copy(),
	}
	ed.Window = vtui.NewWindow(0, 0, width-1, height-2, "")
	var names []string
	for _, s := range core.Settings {
		if len(names) == 0 || names[len(names)-1] != s.Section {
			names = append(names, s.Section)
		}
	}
	names = append(names, allSettings, dataSeparator)
	for _, k := range dataKinds {
		names = append(names, k.name)
	}
	ed.sections = vtui.NewListBox(0, 0, sectionsWidth, 5, names)
	ed.sections.IsSelectable = func(i int) bool { return names[i] != dataSeparator }
	ed.sections.OnSelect = func(i int) {
		if k := kindByName(names[i]); k != nil {
			ed.showData(k)
		} else {
			ed.showSection(names[i])
		}
	}
	ed.sections.OnAction = func(int) { ed.SetFocusedItem(ed.table) }
	// the current section stays marked when the settings have the focus
	ed.sections.AlwaysShowCursor = true
	ed.AddItem(ed.sections)
	ed.columns = []vtui.TableColumn{
		{Title: "Setting", Width: 31},
		{Title: "Value", Width: 0, MinWidth: 10},
		{Title: "Source", Width: 8},
	}
	ed.table = vtui.NewTable(0, 0, 10, 5, ed.columns)
	ed.table.ShowHeader = true
	ed.table.QuickSearch = true
	ed.table.OnSelect = func(int) { ed.updateDescription() }
	ed.table.OnSearchChange = func(string) { ed.updateDescription() }
	ed.table.OnAction = func(int) { ed.edit() }
	ed.AddItem(ed.table)
	for i := range ed.desc {
		ed.desc[i] = vtui.NewText(0, 0, "", 0)
		ed.AddItem(ed.desc[i])
	}
	ed.layout(width, height)
	ed.showSection(names[0])
	ed.SetFocusedItem(ed.table)
	ed.updateTitle()
	return ed, nil
}

// showSection shows the settings of a section, or all settings with
// section titles
func (ed *Editor) showSection(name string) {
	ed.kind = nil
	ed.table.Columns = ed.columns
	ed.rows = ed.rows[:0]
	section := ""
	for _, s := range core.Settings {
		if name == allSettings {
			if s.Section != section {
				section = s.Section
				ed.rows = append(ed.rows, settingRow{ed: ed, section: section})
			}
		} else if s.Section != name {
			continue
		}
		ed.rows = append(ed.rows, settingRow{ed: ed, key: s.Key, section: s.Section})
	}
	rows := make([]vtui.TableRow, len(ed.rows))
	for i, r := range ed.rows {
		rows[i] = r
	}
	ed.table.ClearSearch()
	ed.table.SetRows(rows)
	ed.table.SelectPos, ed.table.TopPos = 0, 0
	if name == allSettings {
		// first setting, not the section title
		ed.table.SelectPos = 1
	}
	ed.updateDescription()
}

// layout places the elements for a screen of width x height
func (ed *Editor) layout(width, height int) {
	ed.width, ed.height = width, height
	ed.Window.SetPosition(0, 0, width-1, height-2)
	bottom := height - 4 // last line inside the frame, with one line of air
	ed.sections.SetPosition(2, 2, 2+sectionsWidth-1, bottom-descLines-1)
	ed.table.SetPosition(2+sectionsWidth+1, 2, width-3, bottom-descLines-1)
	for i, t := range ed.desc {
		y := bottom - descLines + 1 + i
		t.SetPosition(2, y, width-3, y)
	}
	// wrapped for the new width
	ed.updateDescription()
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
	secrets := "ShowPw"
	if ed.secrets {
		secrets = "HidePw"
	}
	labels := map[int][2]string{
		1: {"Help", "Help"}, 2: {"Save", "Save"}, 3: {secrets, "Pwd"}, 4: {"Edit", "Edit"},
		8: {"Reset", "Dflt"}, 10: {"Quit", "End"},
	}
	if ed.kind != nil {
		labels[7], labels[8] = [2]string{"New", "New"}, [2]string{"Delete", "Del"}
	}
	if ed.kind == dkimKind {
		labels[6] = [2]string{"DNS", "DNS"}
	}
	return keyLabels(ed.width, labels)
}

// keyLabels returns key bar labels for a screen width: by function key
// number, the long label if it fits in the key bar slot, else the short one
func keyLabels(width int, labels map[int][2]string) *vtui.KeySet {
	ks := &vtui.KeySet{}
	for n, l := range labels {
		// slot: number, label, one space
		room := width/12 - len(strconv.Itoa(n)) - 1
		if len(l[0]) <= room {
			ks.Normal[n-1] = l[0]
		} else {
			ks.Normal[n-1] = l[1]
		}
	}
	return ks
}

// ProcessKey handles the function keys, other keys go to the table
func (ed *Editor) ProcessKey(e *vtinput.InputEvent) bool {
	if e.KeyDown {
		switch e.VirtualKeyCode {
		case vtinput.VK_F1:
			vtui.FrameManager.Push(helpDialog(ed, helpKeys))
			return true
		case vtinput.VK_F2:
			ed.save()
			return true
		case vtinput.VK_F3:
			ed.secrets = !ed.secrets
			return true
		case vtinput.VK_F4:
			ed.edit()
			return true
		case vtinput.VK_F6:
			if ed.kind == dkimKind {
				ed.showDNS()
				return true
			}
		case vtinput.VK_F7, vtinput.VK_INSERT:
			if ed.kind != nil {
				ed.editItem(true)
				return true
			}
		case vtinput.VK_F8:
			if ed.kind != nil {
				ed.deleteItem()
			} else {
				ed.reset()
			}
			return true
		case vtinput.VK_DELETE:
			// Del edits a quick search first
			if ed.kind != nil && ed.table.SearchText() == "" {
				ed.deleteItem()
				return true
			}
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
// or in a data section
func (ed *Editor) selected() string {
	if ed.kind != nil {
		return ""
	}
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

// dataChanges describes the changes of data, one line each
func (ed *Editor) dataChanges() []string {
	return core.DiffData(ed.savedData, ed.data)
}

// changes returns the number of changed settings and data items
func (ed *Editor) changes() int {
	return len(ed.changed()) + len(ed.dataChanges())
}

func (ed *Editor) updateTitle() {
	title := " cocosmail settings: " + ed.store.Title() + " "
	if n := ed.changes(); n > 0 {
		title = fmt.Sprintf("%s(%d changed) ", title, n)
	}
	ed.SetTitle(title)
}

func (ed *Editor) updateDescription() {
	lines := make([]string, descLines)
	key := ed.selected()
	if ed.kind != nil {
		copy(lines, wrap(ed.kind.help, ed.width-6))
	} else if s, ok := core.SettingByKey(key); ok {
		text := s.Description
		switch {
		case s.Required:
			text += ". Required."
		case s.RequiredWith != "":
			text += ". Required when " + s.RequiredWith + " is true."
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
		t.SetText(literal(lines[i]))
	}
}

// set changes a value being edited
func (ed *Editor) set(key, value string) {
	ed.values[key] = value
	ed.updateTitle()
}

// edit edits the selected setting: bools toggle, choices and text in a
// dialog. In a data section, the selected item.
func (ed *Editor) edit() {
	if ed.kind != nil {
		ed.editItem(false)
		return
	}
	key := ed.selected()
	s, ok := core.SettingByKey(key)
	if !ok {
		return
	}
	if why := ed.store.ReadOnly(key); why != "" {
		ed.message("Read only", core.SettingEnvName(key)+": "+why)
		return
	}
	if _, ok := dsnSettings[key]; ok {
		vtui.FrameManager.Push(newDsnEditor(ed, key))
		return
	}
	if key == "deliverd_local_ips" {
		vtui.FrameManager.Push(newLocalIpsEditor(ed))
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

// check returns why changed settings can't be saved, if they can't
func (ed *Editor) check(changed map[string]string) error {
	if errs := core.ValidateSettings(changed); len(errs) > 0 {
		return errs[0]
	}
	if missing := core.MissingSettings(ed.values); len(missing) > 0 {
		return errors.New("Required: " + strings.Join(missing, ", "))
	}
	return nil
}

// checkAll returns why changes can't be saved, if they can't
func (ed *Editor) checkAll() error {
	if changed := ed.changed(); len(changed) > 0 {
		return ed.check(changed)
	}
	return nil
}

// storeChanges saves changed settings and data, it tells the user if it fails
func (ed *Editor) storeChanges() bool {
	fail := func(err error) bool {
		ed.Err = err
		ed.message("Error", "Not saved: "+err.Error())
		return false
	}
	if changed := ed.changed(); len(changed) > 0 {
		if err := ed.store.Save(changed); err != nil {
			return fail(err)
		}
		ed.saved = copyValues(ed.values)
	}
	if len(ed.dataChanges()) > 0 {
		if err := ed.store.SaveData(ed.savedData, ed.data); err != nil {
			ed.updateTitle()
			return fail(err)
		}
		// with changes made elsewhere meanwhile
		data, err := ed.store.LoadData()
		if err != nil {
			return fail(err)
		}
		ed.data, ed.savedData = data, data.Copy()
		if ed.kind != nil {
			ed.refreshData()
		}
	}
	ed.Err = nil
	ed.updateTitle()
	return true
}

// save checks and saves changed settings and data, after confirmation
func (ed *Editor) save() {
	changed := ed.changed()
	dataChanges := ed.dataChanges()
	if len(changed) == 0 && len(dataChanges) == 0 {
		ed.message("Save", "Nothing changed.")
		return
	}
	if err := ed.checkAll(); err != nil {
		ed.message("Error", err.Error())
		return
	}
	keys := sortedKeys(changed)
	lines := make([]string, 0, len(keys)+len(dataChanges))
	for _, k := range keys {
		lines = append(lines, k+" = "+ed.displayValue(k))
	}
	lines = append(lines, dataChanges...)
	var text strings.Builder
	for i, l := range lines {
		if i == 8 {
			fmt.Fprintf(&text, "and %d more\n", len(lines)-8)
			break
		}
		text.WriteString(l + "\n")
	}
	if len(keys) > 0 {
		text.WriteString("\n" + ed.store.ApplyNote(keys))
	}
	if ed.values["smtpd_launch"] != "true" && ed.values["deliverd_launch"] != "true" && ed.values["pop3d_launch"] != "true" {
		text.WriteString("\nNote: nothing will run, smtpd_launch, deliverd_launch and pop3d_launch are all false.")
	}
	dlg := vtui.ShowMessage("Save", literal(text.String()), []string{"&Save", "&Cancel"})
	dlg.OnResult = func(code int) {
		if code == 0 {
			ed.storeChanges()
		}
	}
}

// quit quits, asking what to do with unsaved changes
func (ed *Editor) quit() {
	n := ed.changes()
	if n == 0 {
		ed.doQuit()
		return
	}
	text := "1 change is not saved.\nSave it before quitting?"
	if n > 1 {
		text = fmt.Sprintf("%d changes are not saved.\nSave them before quitting?", n)
	}
	dlg := vtui.ShowMessage("Quit", text, []string{"&Save", "&Don't save", "&Cancel"})
	dlg.OnResult = func(code int) {
		switch code {
		case 0:
			if err := ed.checkAll(); err != nil {
				ed.message("Error", err.Error())
				return
			}
			if ed.storeChanges() {
				ed.doQuit()
			}
		case 1:
			ed.doQuit()
		}
	}
}

// helpKeys are shown by the help dialog
var helpKeys = [][2]string{
	{"F1", "This help"},
	{"F2", "Save changes, after showing what changed"},
	{"F3", "Show or hide passwords and other secret values"},
	{"F4, Enter", "Edit the selected setting (true/false ones are switched)"},
	{"F8", "Reset the selected setting to its default"},
	{"", "In data sections (Domains, Users...):"},
	{"F4, Enter", "Edit the selected item"},
	{"F7, Ins", "Add an item"},
	{"F8, Del", "Delete the selected item"},
	{"F6", "DKIM keys: show the DNS record"},
	{"", ""},
	{"F10, Esc", "Quit, asks to save unsaved changes"},
	{"Tab", "Switch between the section list and the settings"},
	{"Typing", "Search a setting by name in the section, Esc clears"},
	{"Ctrl+A", "In a field: select the whole value, typing replaces it"},
}

// helpDialog returns the dialog listing keys
func helpDialog(ed *Editor, helpKeys [][2]string) *vtui.Window {
	keyW, textW := 0, 0
	for _, k := range helpKeys {
		if len(k[0]) > keyW {
			keyW = len(k[0])
		}
		if len(k[1]) > textW {
			textW = len(k[1])
		}
	}
	w := keyW + textW + 8
	h := len(helpKeys) + 7
	x1, y1 := (ed.width-w)/2, (ed.height-1-h)/2
	dlg := vtui.NewDialog(x1, y1, x1+w-1, y1+h-1, " Help ")
	for i, k := range helpKeys {
		dlg.AddItem(vtui.NewText(x1+2, y1+2+i, literal(k[0]), 0))
		dlg.AddItem(vtui.NewText(x1+2+keyW+2, y1+2+i, literal(k[1]), 0))
	}
	ok := vtui.NewButton(0, 0, "&Ok")
	ok.IsDefault = true
	y := y1 + 2 + len(helpKeys) + 1
	ok.SetPosition(x1+(w-6)/2, y, x1+(w-6)/2+ok.X2-ok.X1, y)
	ok.OnClick = func() { dlg.SetExitCode(1) }
	dlg.AddItem(ok)
	return dlg
}

func (ed *Editor) doQuit() {
	if ed.Quit != nil {
		ed.Quit()
	}
}

func (ed *Editor) message(title, text string) {
	vtui.ShowMessage(title, literal(text), []string{"&Ok"})
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
		dlg.AddItem(vtui.NewText(x1+2, y1+2+i, literal(l), 0))
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
		edit := newEdit(x1+2, y, w-4, ed.values[s.Key])
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
	setPalette()
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

// setPalette adjusts vtui's palette: selected text in input fields is white on
// blue. vtui's is black on light grey, like the dialog background, or dark grey
// on cyan after select all (Ctrl+A), like the field: both hardly visible.
func setPalette() {
	selected := vtui.SetRGBBoth(0, 0xFFFFFF, 0x0000A0)
	vtui.Palette[vtui.ColDialogEditSelected] = selected
	vtui.Palette[vtui.ColDialogEditUnchanged] = selected
}

// literal escapes & in text shown by vtui, where & marks a hotkey
func literal(text string) string {
	return strings.ReplaceAll(text, "&", "&&")
}

// newEdit returns an Edit with value, in the normal text color and the cursor
// at the end. vtui's default text would be selected, replaced by typing, and
// shown dark grey on cyan: hardly readable.
func newEdit(x, y, width int, value string) *vtui.Edit {
	e := vtui.NewEdit(x, y, width, "")
	e.SetText(value)
	return e
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
