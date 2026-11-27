package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
	"github.com/yarrasatwik/gatecrasher/internal/model"
)

// identityExposure maps identity overrides (from the environment document)
// and the traits stored on those identities (Admin API, read-only). With
// "Hide sensitive data" off, the public identities endpoint returns both to
// anyone who knows or guesses the identifier — usually an email address.
func (a *App) identityExposure(ctx context.Context, eng *flagsmith.Engine, env flagsmith.Environment) []model.Finding {
	if env.HideSensitiveData {
		return nil
	}
	base := eng.EvaluateEnvironment()
	var out []model.Finding
	for _, idm := range eng.Doc.IdentityOverrides {
		if idm == nil || idm.Identifier == "" {
			continue
		}
		var changes []model.FlagChange
		for _, fs := range idm.IdentityFeatures {
			if fs == nil || fs.Feature == nil {
				continue
			}
			name := fs.Feature.Name
			after := flagsmith.Flag{Enabled: fs.Enabled, Value: fs.RawValue}.State()
			if b, ok := base[name]; !ok || b.State() != after {
				changes = append(changes, model.FlagChange{Flag: name, Before: base[name].State(), After: after})
			}
		}
		traitKeys := a.identityTraitKeys(ctx, env, idm.Identifier)
		if len(changes) == 0 && len(traitKeys) == 0 {
			continue
		}
		masked := maskIdentifier(idm.Identifier)
		if len(changes) > 0 {
			out = append(out, model.Finding{
				ID: model.MakeFindingID(model.FIdentityOverrideLeak, env.Name, idm.Identifier), Type: model.FIdentityOverrideLeak,
				Title:       fmt.Sprintf("Identity override for %s reveals %d targeted flag(s) to anyone who knows the identifier", masked, len(changes)),
				Environment: env.Name, Subject: masked, DetectedBy: []model.Method{model.MethodEngine, model.MethodSettings},
				Confirmed: true, Status: model.StatusExploitable, Unlocked: changes,
				Evidence: []model.Evidence{{Kind: "engine", Note: "Identity override present in the environment document while \"Hide sensitive data\" is off."}},
			})
		}
		if len(traitKeys) > 0 {
			out = append(out, model.Finding{
				ID: model.MakeFindingID(model.FIdentityTraitLeak, env.Name, idm.Identifier), Type: model.FIdentityTraitLeak,
				Title:       fmt.Sprintf("Traits of %s (%s) are readable with the public client key", masked, strings.Join(traitKeys, ", ")),
				Environment: env.Name, Subject: masked, Category: model.CatPII, DetectedBy: []model.Method{model.MethodSettings},
				Confirmed: true, Status: model.StatusExploitable,
				Repro: flagsmith.Repro("GET", strings.TrimRight(a.Cfg.Flagsmith.APIURL, "/")+"/identities/?identifier=<IDENTIFIER>", nil),
				Evidence: []model.Evidence{{Kind: "setting",
					Note: fmt.Sprintf("Identity stores %d trait(s); \"Hide sensitive data\" is off, so GET identities/?identifier= returns them. Trait values are not read by Gatecrasher.", len(traitKeys))}},
			})
		}
	}
	return out
}

// identityTraitKeys lists trait KEYS (never values) stored on an identity.
func (a *App) identityTraitKeys(ctx context.Context, env flagsmith.Environment, identifier string) []string {
	var page struct {
		Results []struct {
			ID         int    `json:"id"`
			Identifier string `json:"identifier"`
		} `json:"results"`
	}
	if err := a.Admin.Get(ctx, "environments/"+url.PathEscape(env.APIKey)+"/identities/?q="+url.QueryEscape(identifier), &page); err != nil {
		return nil
	}
	for _, r := range page.Results {
		if r.Identifier != identifier {
			continue
		}
		var raw json.RawMessage
		if err := a.Admin.Get(ctx, fmt.Sprintf("environments/%s/identities/%d/traits/", url.PathEscape(env.APIKey), r.ID), &raw); err != nil {
			return nil
		}
		var traits []struct {
			Key string `json:"trait_key"`
		}
		if err := json.Unmarshal(raw, &traits); err != nil {
			var pg struct {
				Results []struct {
					Key string `json:"trait_key"`
				} `json:"results"`
			}
			if json.Unmarshal(raw, &pg) != nil {
				return nil
			}
			traits = pg.Results
		}
		keys := make([]string, 0, len(traits))
		for _, t := range traits {
			keys = append(keys, t.Key)
		}
		sort.Strings(keys)
		return keys
	}
	return nil
}

// maskIdentifier keeps enough of an identifier to recognise it in a report
// without printing a full email address: "ce***@acmeshop.dev".
func maskIdentifier(id string) string {
	local, domain, ok := strings.Cut(id, "@")
	if !ok {
		if len(id) <= 4 {
			return "***"
		}
		return id[:2] + "***"
	}
	if len(local) > 2 {
		local = local[:2]
	}
	return local + "***@" + domain
}
