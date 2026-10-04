package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// commandParams maps each command that takes parameters to its params
// type. The schemas of the other commands must declare no properties.
var commandParams = map[CMD]any{
	CmdOpenStorage:          OpenStorageParams{},
	CmdSubmitPassphrase:     SubmitPassphraseParams{},
	CmdStartServer:          StartServerParams{},
	CmdDial:                 DialParams{},
	CmdSendMessage:          SendMessageParams{},
	CmdCloseSession:         CloseSessionParams{},
	CmdRenameSession:        RenameSessionParams{},
	CmdGenerateRelayToken:   GenerateRelayTokenParams{},
	CmdRemoveRelayToken:     RemoveRelayTokenParams{},
	CmdGenerateP2PToken:     GenerateP2PTokenParams{},
	CmdRemoveP2PToken:       RemoveP2PTokenParams{},
	CmdVerifyResponse:       VerifyResponseParams{},
	CmdSetVerificationMode:  SetVerificationModeParams{},
	CmdGetHistoryMessages:   GetHistoryMessagesParams{},
	CmdLoadHistory:          LoadHistoryParams{},
	CmdRenameHistorySession: RenameHistorySessionParams{},
	CmdDeleteHistorySession: DeleteHistorySessionParams{},
	CmdDeletePeer:           DeletePeerParams{},
	CmdSetMyName:            SetMyNameParams{},
	CmdSetIncognito:         SetIncognitoParams{},
	CmdAddPeer:              AddPeerParams{},
	CmdRenamePeer:           RenamePeerParams{},
	CmdGetPeer:              GetPeerParams{},
	CmdGetSessionInfo:       GetSessionInfoParams{},
	CmdExportLogs:           ExportLogsParams{},
	CmdSetLogLevel:          SetLogLevelParams{},
	CmdSetFingerprintFormat: SetFingerprintFormatParams{},
}

// protocolNames returns the values of the string constants of type typ
// that main.go declares, sorted.
func protocolNames(t *testing.T, typ string) []string {
	a := require.New(t)
	f, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	a.NoError(err)
	var names []string
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != typ {
				continue
			}
			for _, v := range vs.Values {
				lit, ok := v.(*ast.BasicLit)
				a.True(ok && lit.Kind == token.STRING)
				name, err := strconv.Unquote(lit.Value)
				a.NoError(err)
				names = append(names, name)
			}
		}
	}
	slices.Sort(names)
	return names
}

// schemaNames returns the names of the schemas in schema/dir, sorted.
func schemaNames(t *testing.T, dir string) []string {
	a := require.New(t)
	entries, err := os.ReadDir(filepath.Join("schema", dir))
	a.NoError(err)
	var names []string
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".schema.json")
		a.True(ok, "%s/%s is not a schema", dir, e.Name())
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func loadSchema(t *testing.T, path string) map[string]any {
	a := require.New(t)
	data, err := os.ReadFile(filepath.Join("schema", path))
	a.NoError(err)
	var schema map[string]any
	a.NoError(json.Unmarshal(data, &schema), path)
	return schema
}

// jsonFields returns the names that encoding/json gives the fields of the
// struct v, sorted.
func jsonFields(v any) []string {
	typ := reflect.TypeOf(v)
	var names []string
	for i := range typ.NumField() {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		switch name {
		case "-":
			continue
		case "":
			name = f.Name
		}
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func propertyNames(schema map[string]any) []string {
	props, _ := schema["properties"].(map[string]any)
	names := make([]string, 0, len(props))
	for name := range props {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// requiredNames returns the names that schema, its allOf, anyOf and if
// branches and their then and else branches require.
func requiredNames(schema map[string]any) []string {
	var names []string
	for _, r := range asList(schema["required"]) {
		name, _ := r.(string)
		names = append(names, name)
	}
	for _, key := range []string{"allOf", "anyOf"} {
		for _, sub := range asList(schema[key]) {
			names = append(names, requiredNames(asMap(sub))...)
		}
	}
	for _, key := range []string{"if", "then", "else", "not"} {
		if sub, ok := schema[key].(map[string]any); ok {
			names = append(names, requiredNames(sub)...)
		}
	}
	return names
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// schemaAccepts reports whether params satisfy the parts of schema that
// the command schemas use to say which params are required: required,
// const and enum of properties, allOf, anyOf, not, and if with then and
// else. It checks no types or formats.
func schemaAccepts(schema, params map[string]any) bool {
	for _, r := range asList(schema["required"]) {
		if _, ok := params[r.(string)]; !ok {
			return false
		}
	}
	for name, prop := range asMap(schema["properties"]) {
		v, ok := params[name]
		if !ok {
			continue
		}
		p := asMap(prop)
		if c, ok := p["const"]; ok && c != v {
			return false
		}
		if enum, ok := p["enum"]; ok && !slices.Contains(asList(enum), v) {
			return false
		}
	}
	for _, sub := range asList(schema["allOf"]) {
		if !schemaAccepts(asMap(sub), params) {
			return false
		}
	}
	if anyOf := asList(schema["anyOf"]); len(anyOf) > 0 &&
		!slices.ContainsFunc(anyOf, func(sub any) bool {
			return schemaAccepts(asMap(sub), params)
		}) {
		return false
	}
	if not, ok := schema["not"].(map[string]any); ok &&
		schemaAccepts(not, params) {
		return false
	}
	if cond, ok := schema["if"].(map[string]any); ok {
		branch := "else"
		if schemaAccepts(cond, params) {
			branch = "then"
		}
		if sub, ok := schema[branch].(map[string]any); ok &&
			!schemaAccepts(sub, params) {
			return false
		}
	}
	return true
}

// Every command and event the daemon knows has a schema, and every schema
// is for one it knows.
func TestSchemasCoverProtocol(t *testing.T) {
	a := require.New(t)
	a.Equal(protocolNames(t, "CMD"), schemaNames(t, "commands"))
	a.Equal(protocolNames(t, "Evt"), schemaNames(t, "events"))
}

// Each schema is a JSON Schema 2020-12 object schema whose required
// names are among its properties.
func TestSchemasAreWellFormed(t *testing.T) {
	var paths []string
	for _, dir := range []string{"_shared", "commands", "events"} {
		entries, err := os.ReadDir(filepath.Join("schema", dir))
		require.New(t).NoError(err)
		for _, e := range entries {
			paths = append(paths, filepath.Join(dir, e.Name()))
		}
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			a := require.New(t)
			schema := loadSchema(t, path)
			a.Equal("https://json-schema.org/draft/2020-12/schema",
				schema["$schema"])
			a.NotEmpty(schema["$id"])
			a.NotEmpty(schema["title"])
			a.NotEmpty(schema["description"])
			if ref, ok := schema["$ref"].(string); ok {
				_, err := os.Stat(filepath.Join("schema",
					filepath.Dir(path), ref))
				a.NoError(err, "$ref %s", ref)
				return
			}
			a.Equal("object", schema["type"])
			props := propertyNames(schema)
			for _, name := range requiredNames(schema) {
				a.Contains(props, name, "required but not a property")
			}
		})
	}
}

// The properties of each command schema are the JSON fields of the
// command's params type.
func TestCommandSchemasMatchParams(t *testing.T) {
	for _, name := range protocolNames(t, "CMD") {
		t.Run(name, func(t *testing.T) {
			a := require.New(t)
			schema := loadSchema(t, filepath.Join(
				"commands", name+".schema.json",
			))
			params, ok := commandParams[CMD(name)]
			if !ok {
				a.Empty(propertyNames(schema),
					"add the command's params type to commandParams")
				a.Equal(false, schema["additionalProperties"])
				return
			}
			a.Equal(jsonFields(params), propertyNames(schema))
		})
	}
}

// The schemas of the payloads that the daemon writes from a struct list
// the struct's JSON fields.
func TestEventSchemasMatchStructs(t *testing.T) {
	tests := []struct {
		path  string
		items bool
		value any
	}{
		{path: "_shared/session-info.schema.json", value: SessionInfo{}},
		{path: "_shared/relay-token.schema.json", value: relayToken{}},
		{path: "events/log_entry.schema.json", value: LogEntryInfo{}},
		{
			path: "events/p2p_tokens.schema.json", items: true,
			value: p2pToken{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			a := require.New(t)
			schema := loadSchema(t, tt.path)
			if tt.items {
				tokens := asMap(asMap(schema["properties"])["tokens"])
				schema = asMap(tokens["items"])
			}
			a.Equal(jsonFields(tt.value), propertyNames(schema))
		})
	}
}

// The start_server and dial schemas take the transports that the daemon
// takes, and require addr for exactly those that need one.
func TestTransportSchemas(t *testing.T) {
	d := newQuietDaemon()
	t.Cleanup(d.cancel)
	want := []any{""}
	for _, tr := range transports {
		want = append(want, tr)
	}
	cases := append([]string{"", "absent", "bogus"}, transports...)
	for _, name := range []string{"start_server", "dial"} {
		schema := loadSchema(t, "commands/"+name+".schema.json")
		transport := asMap(asMap(schema["properties"])["transport"])
		require.New(t).ElementsMatch(want, asList(transport["enum"]))

		for _, tr := range cases {
			t.Run(name+"/"+tr, func(t *testing.T) {
				a := require.New(t)
				// Every field but addr, so that only addr can be
				// missing.
				params := map[string]any{
					"relay_addr":       "relay.example.com:443",
					"token":            strings.Repeat("ab", 16),
					"broker_addr":      "broker.example.com:4788",
					"p2p_token":        strings.Repeat("ab", 16),
					"direct_peer_addr": "192.0.2.1:9000",
				}
				if tr != "absent" {
					params["transport"] = tr
				}
				given := tr
				if tr == "absent" {
					given = ""
				}

				_, ok := d.checkTransport("", given, "")
				a.Equal(ok, schemaAccepts(schema, params),
					"schema and daemon disagree on a missing addr")
				params["addr"] = "127.0.0.1:9000"
				_, ok = d.checkTransport("", given, "127.0.0.1:9000")
				a.Equal(ok, schemaAccepts(schema, params),
					"schema and daemon disagree on the transport")
			})
		}
	}
}
